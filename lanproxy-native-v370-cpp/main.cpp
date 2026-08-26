#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <d2d1.h>
#include <dwrite.h>
#include <shellapi.h>
#include <shlobj.h>
#include <stdint.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

static constexpr wchar_t kClassName[] = L"LANProxyShareAssistantCpp";
static constexpr wchar_t kTitle[] = L"局域网代理共享助手";
static constexpr wchar_t kVersion[] = L"3.7.0";
static constexpr UINT WM_APP_SCAN_DONE = WM_APP + 1;
static constexpr UINT WM_APP_ACTION_DONE = WM_APP + 2;
static constexpr UINT WM_APP_DEVICES_DONE = WM_APP + 3;
static constexpr UINT_PTR TIMER_ID = 1;

struct ScopedCom {
    IUnknown* p = nullptr;
    ScopedCom() = default;
    explicit ScopedCom(IUnknown* v) : p(v) {}
    ~ScopedCom() { if (p) p->Release(); }
};

template <typename T> static void SafeRelease(T*& p) { if (p) { p->Release(); p = nullptr; } }

static std::wstring Trim(const std::wstring& s) {
    size_t a = s.find_first_not_of(L" \r\n\t");
    if (a == std::wstring::npos) return L"";
    size_t b = s.find_last_not_of(L" \r\n\t");
    return s.substr(a, b - a + 1);
}

static std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

static bool IsPrivateIPv4(uint32_t host) {
    uint8_t a = (host >> 24) & 0xff, b = (host >> 16) & 0xff;
    return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168);
}

static std::wstring IPv4ToString(uint32_t addrNetOrder) {
    IN_ADDR a{}; a.S_un.S_addr = addrNetOrder;
    wchar_t buf[64]{};
    if (InetNtopW(AF_INET, &a, buf, ARRAYSIZE(buf))) return buf;
    return L"";
}

static int PortFromDWORD(DWORD p) { return ntohs((u_short)p); }

static std::wstring GetProcessName(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t path[32768]{}; DWORD n = ARRAYSIZE(path);
    std::wstring out;
    if (QueryFullProcessImageNameW(h, 0, path, &n)) {
        const wchar_t* base = wcsrchr(path, L'\\');
        out = base ? base + 1 : path;
    }
    CloseHandle(h);
    return out;
}

static bool SetSocketTimeout(SOCKET s, int ms) {
    DWORD v = ms;
    return setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&v), sizeof(v)) == 0 &&
           setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&v), sizeof(v)) == 0;
}

static SOCKET ConnectLocal(int port, int timeoutMs = 350) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    SetSocketTimeout(s, timeoutMs);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port); InetPtonW(AF_INET, L"127.0.0.1", &sa.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

static bool ProbeSocks5(int port) {
    SOCKET s = ConnectLocal(port, 220); if (s == INVALID_SOCKET) return false;
    unsigned char req[3] = {5,1,0};
    bool ok = send(s, reinterpret_cast<char*>(req), 3, 0) == 3;
    unsigned char resp[2]{};
    if (ok) ok = recv(s, reinterpret_cast<char*>(resp), 2, 0) == 2 && resp[0] == 5;
    closesocket(s); return ok;
}

static bool ProbeHttp(int port) {
    SOCKET s = ConnectLocal(port, 220); if (s == INVALID_SOCKET) return false;
    const char* req = "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nProxy-Connection: close\r\n\r\n";
    bool ok = send(s, req, (int)strlen(req), 0) > 0;
    char buf[64]{}; int n = ok ? recv(s, buf, sizeof(buf)-1, 0) : -1;
    closesocket(s);
    if (n <= 0) return false;
    std::string r(buf, buf+n);
    return r.find("HTTP/") != std::string::npos;
}

struct ScanResult {
    std::wstring ip;
    std::wstring adapter;
    std::wstring process;
    int httpPort = 0;
    int socksPort = 0;
};

static ScanResult DetectEnvironment() {
    ScanResult out;
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER, nullptr, nullptr, &size);
    std::vector<unsigned char> buf(size);
    auto aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER, nullptr, aa, &size) == NO_ERROR) {
        int best = -999;
        for (auto a = aa; a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfType == IF_TYPE_TUNNEL) continue;
            for (auto u = a->FirstUnicastAddress; u; u = u->Next) {
                if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
                auto sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
                uint32_t host = ntohl(sin->sin_addr.S_un.S_addr);
                if (!IsPrivateIPv4(host)) continue;
                int score = 10;
                if (a->IfType == IF_TYPE_ETHERNET_CSMACD) score += 15;
                if (a->IfType == IF_TYPE_IEEE80211) score += 14;
                std::wstring desc = a->FriendlyName ? a->FriendlyName : L"局域网";
                auto low = Lower(desc);
                if (low.find(L"virtual") != std::wstring::npos || low.find(L"vpn") != std::wstring::npos || low.find(L"tap") != std::wstring::npos || low.find(L"hyper-v") != std::wstring::npos) score -= 20;
                if (score > best) { best = score; out.ip = IPv4ToString(sin->sin_addr.S_un.S_addr); out.adapter = desc; }
            }
        }
    }

    ULONG sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    std::vector<unsigned char> tb(sz);
    auto table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(tb.data());
    struct Cand { int port; DWORD pid; std::wstring proc; int score; };
    std::vector<Cand> cands;
    if (GetExtendedTcpTable(table, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) == NO_ERROR) {
        for (DWORD i=0;i<table->dwNumEntries;i++) {
            const auto& r = table->table[i];
            int p = PortFromDWORD(r.dwLocalPort);
            if (p <= 0 || p > 65535) continue;
            uint32_t host = ntohl(r.dwLocalAddr);
            if (!(host == 0 || (host >> 24) == 127)) continue;
            std::wstring proc = GetProcessName(r.dwOwningPid);
            int score = 0; auto low = Lower(proc);
            if (low.find(L"quickq") != std::wstring::npos || low.find(L"clash") != std::wstring::npos || low.find(L"v2ray") != std::wstring::npos || low.find(L"sing-box") != std::wstring::npos || low.find(L"mihomo") != std::wstring::npos) score += 20;
            cands.push_back({p, r.dwOwningPid, proc, score});
        }
    }
    std::sort(cands.begin(), cands.end(), [](const Cand&a,const Cand&b){ return a.score>b.score; });
    int bestHttp=-999, bestSocks=-999;
    for (size_t i=0;i<cands.size() && i<80;i++) {
        const auto& c = cands[i];
        if (ProbeHttp(c.port)) {
            int s = c.score + 40;
            if (s > bestHttp) { bestHttp=s; out.httpPort=c.port; if (!c.proc.empty()) out.process=c.proc; }
        }
        if (ProbeSocks5(c.port)) {
            int s = c.score + 40;
            if (s > bestSocks) { bestSocks=s; out.socksPort=c.port; if (out.process.empty() && !c.proc.empty()) out.process=c.proc; }
        }
    }
    return out;
}

class RelayServer {
public:
    RelayServer() = default;
    ~RelayServer(){ Stop(); }
    bool Start(const std::wstring& ip, int listenPort, int targetPort) {
        Stop();
        targetPort_ = targetPort;
        listen_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if (listen_ == INVALID_SOCKET) return false;
        BOOL reuse = TRUE; setsockopt(listen_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&reuse), sizeof(reuse));
        sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons((u_short)listenPort); if (InetPtonW(AF_INET, ip.c_str(), &sa.sin_addr) != 1) return false;
        if (bind(listen_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0 || listen(listen_, 32) != 0) { closesocket(listen_); listen_=INVALID_SOCKET; return false; }
        running_=true; th_=std::thread([this]{ AcceptLoop(); }); return true;
    }
    void Stop() {
        running_=false;
        if (listen_ != INVALID_SOCKET) { closesocket(listen_); listen_=INVALID_SOCKET; }
        if (th_.joinable()) th_.join();
        std::lock_guard<std::mutex> lk(mu_); for (SOCKET s: conns_) closesocket(s); conns_.clear();
    }
private:
    void Track(SOCKET s, bool add) { std::lock_guard<std::mutex> lk(mu_); if(add) conns_.insert(s); else conns_.erase(s); }
    void AcceptLoop() {
        while (running_) {
            SOCKET c = accept(listen_, nullptr, nullptr); if (c == INVALID_SOCKET) break;
            std::thread([this,c]{ Bridge(c); }).detach();
        }
    }
    void Bridge(SOCKET c) {
        Track(c,true);
        SOCKET u = ConnectLocal(targetPort_, 1000);
        if (u==INVALID_SOCKET) { Track(c,false); closesocket(c); return; }
        Track(u,true);
        std::atomic<int> done{0};
        auto pump=[&](SOCKET a, SOCKET b){ char bfr[8192]; for(;;){ int n=recv(a,bfr,sizeof(bfr),0); if(n<=0) break; int off=0; while(off<n){ int m=send(b,bfr+off,n-off,0); if(m<=0){ off=n; break; } off+=m; } } shutdown(b,SD_SEND); done++; };
        std::thread t1(pump,c,u), t2(pump,u,c); t1.join(); t2.join();
        Track(c,false); Track(u,false); closesocket(c); closesocket(u);
    }
    SOCKET listen_=INVALID_SOCKET; int targetPort_=0; std::atomic<bool> running_{false}; std::thread th_; std::mutex mu_; std::set<SOCKET> conns_;
};

struct DeviceInfo { std::wstring ip; std::wstring mac; int active=0; std::wstring firstSeen; std::wstring lastSeen; };
static std::mutex gDeviceMu; static std::map<std::wstring,std::wstring> gFirstSeen;

static std::wstring NowClock() {
    SYSTEMTIME st{}; GetLocalTime(&st); wchar_t b[32]{}; swprintf_s(b,L"%02d:%02d:%02d",st.wHour,st.wMinute,st.wSecond); return b;
}

static std::wstring MacForIPv4(const std::wstring& ip) {
    IN_ADDR a{}; if (InetPtonW(AF_INET, ip.c_str(), &a)!=1) return L"";
    ULONG mac[2]{}; ULONG len=6; if (SendARP(a.S_un.S_addr,0,mac,&len)!=NO_ERROR || len==0) return L"";
    BYTE* p=reinterpret_cast<BYTE*>(mac); std::wstringstream ss; ss<<std::hex<<std::uppercase;
    for(ULONG i=0;i<len;i++){ if(i) ss<<L":"; ss.width(2); ss.fill(L'0'); ss<<(int)p[i]; } return ss.str();
}

static std::vector<DeviceInfo> EnumerateDevices(int listenPort) {
    std::map<std::wstring,int> counts;
    ULONG sz=0; GetExtendedTcpTable(nullptr,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0); std::vector<unsigned char> b(sz);
    auto t=reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(b.data()); DWORD self=GetCurrentProcessId();
    if(GetExtendedTcpTable(t,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)==NO_ERROR){
        for(DWORD i=0;i<t->dwNumEntries;i++){ const auto&r=t->table[i]; if(r.dwOwningPid!=self || PortFromDWORD(r.dwLocalPort)!=listenPort || r.dwState!=MIB_TCP_STATE_ESTAB) continue; std::wstring ip=IPv4ToString(r.dwRemoteAddr); if(ip.empty()||ip==L"127.0.0.1") continue; counts[ip]++; }
    }
    std::vector<DeviceInfo> out; std::wstring now=NowClock(); std::lock_guard<std::mutex> lk(gDeviceMu);
    for(auto&kv:counts){ if(!gFirstSeen.count(kv.first)) gFirstSeen[kv.first]=now; out.push_back({kv.first,MacForIPv4(kv.first),kv.second,gFirstSeen[kv.first],now}); }
    return out;
}

enum class Page { Home, Phone, Devices, Advanced };
enum class HitAction { None, NavPhone, NavDevices, NavAdvanced, Back, Rescan, Start, Stop, Test, ViewDevices, Android, IOS, RefreshDevices, ClearLogs, CopyLogs, ResetPorts, ToggleSocks, Minimize, Close };
struct Hit { D2D1_RECT_F r{}; HitAction a=HitAction::None; };

struct AppState {
    HWND hwnd=nullptr; Page page=Page::Home; bool ios=false; bool sharing=false; bool shareSocks=false; std::atomic<bool> scanning{false}; std::atomic<bool> deviceScan{false};
    std::wstring ip=L"检测中…"; std::wstring adapter=L""; std::wstring process=L"正在检测"; int httpLocal=0,socksLocal=0,httpLan=18800,socksLan=11020;
    std::vector<DeviceInfo> devices; std::vector<std::wstring> logs; std::vector<Hit> hits; std::wstring toast; std::chrono::steady_clock::time_point toastUntil{},shareStart{}; std::wstring lastSync;
    RelayServer httpRelay,socksRelay;
    ID2D1Factory* d2d=nullptr; ID2D1HwndRenderTarget* rt=nullptr; IDWriteFactory* dw=nullptr;
    IDWriteTextFormat *f12=nullptr,*f13=nullptr,*f14=nullptr,*f16=nullptr,*f20=nullptr,*f24=nullptr,*fMono=nullptr;
    HWND edits[4]{}; HFONT editFont=nullptr;
} g;

static D2D1_COLOR_F C(UINT32 rgb, float a=1.f){ return D2D1::ColorF(((rgb>>16)&255)/255.f,((rgb>>8)&255)/255.f,(rgb&255)/255.f,a); }
static const UINT32 COL_BG=0xF3F7FC, COL_CARD=0xFFFFFF, COL_BORDER=0xD9E3F0, COL_TEXT=0x122033, COL_MUTED=0x61738A, COL_BLUE=0x2563EB, COL_BLUE2=0xEEF4FF, COL_GREEN=0x16A34A, COL_GREENBG=0xECFDF3;

static ID2D1SolidColorBrush* Brush(UINT32 rgb,float a=1.f){ ID2D1SolidColorBrush* b=nullptr; if(g.rt) g.rt->CreateSolidColorBrush(C(rgb,a),&b); return b; }
static void FillRR(D2D1_RECT_F r,float rad,UINT32 rgb){ auto b=Brush(rgb); if(b){ g.rt->FillRoundedRectangle(D2D1::RoundedRect(r,rad,rad),b); b->Release(); } }
static void StrokeRR(D2D1_RECT_F r,float rad,UINT32 rgb,float w=1.f){ auto b=Brush(rgb); if(b){ g.rt->DrawRoundedRectangle(D2D1::RoundedRect(r,rad,rad),b,w); b->Release(); } }
static void Line(float x1,float y1,float x2,float y2,UINT32 rgb,float w=1.f){ auto b=Brush(rgb); if(b){ g.rt->DrawLine({x1,y1},{x2,y2},b,w); b->Release(); } }
static void Circle(float x,float y,float r,UINT32 fill){ auto b=Brush(fill); if(b){ g.rt->FillEllipse(D2D1::Ellipse({x,y},r,r),b); b->Release(); } }
static void Text(const std::wstring&s,D2D1_RECT_F r,IDWriteTextFormat*f,UINT32 col,bool clip=true){ auto b=Brush(col); if(b){ g.rt->DrawTextW(s.c_str(),(UINT32)s.size(),f,r,b,clip?D2D1_DRAW_TEXT_OPTIONS_CLIP:D2D1_DRAW_TEXT_OPTIONS_NONE); b->Release(); } }
static void AddHit(D2D1_RECT_F r,HitAction a){ g.hits.push_back({r,a}); }

static void Button(D2D1_RECT_F r,const std::wstring&label,HitAction a,bool primary=false,bool disabled=false){
    FillRR(r,7,disabled?0xF3F5F8:(primary?COL_BLUE:0xFFFFFF)); StrokeRR(r,7,disabled?0xE4E8EF:(primary?COL_BLUE:COL_BORDER));
    Text(label,{r.left,r.top+8,r.right,r.bottom},g.f14,disabled?0x9BA8B8:(primary?0xFFFFFF:COL_TEXT)); if(!disabled) AddHit(r,a);
}
static void Pill(D2D1_RECT_F r,const std::wstring&label,UINT32 bg,UINT32 fg){ FillRR(r,10,bg); Text(label,{r.left,r.top+4,r.right,r.bottom},g.f12,fg); }
static void Card(D2D1_RECT_F r,bool blue=false){ FillRR(r,10,COL_CARD); StrokeRR(r,10,blue?0xB9D1FF:COL_BORDER); }

static void DrawBrandIcon(float x,float y,float s){
    FillRR({x,y,x+s,y+s},10,COL_BLUE); auto b=Brush(0xFFFFFF); if(!b)return;
    g.rt->DrawLine({x+s*.34f,y+s*.50f},{x+s*.66f,y+s*.31f},b,2.3f); g.rt->DrawLine({x+s*.34f,y+s*.50f},{x+s*.66f,y+s*.69f},b,2.3f);
    g.rt->FillEllipse(D2D1::Ellipse({x+s*.31f,y+s*.50f},3.2f,3.2f),b); g.rt->FillEllipse(D2D1::Ellipse({x+s*.69f,y+s*.29f},3.2f,3.2f),b); g.rt->FillEllipse(D2D1::Ellipse({x+s*.69f,y+s*.71f},3.2f,3.2f),b); b->Release();
}
static void DrawSmallIcon(float x,float y,int kind,UINT32 bg=0xEEF4FF,UINT32 fg=COL_BLUE){
    FillRR({x,y,x+28,y+28},7,bg); auto b=Brush(fg); if(!b)return;
    if(kind==0){ g.rt->DrawEllipse(D2D1::Ellipse({x+14,y+14},7,7),b,1.3f); g.rt->DrawLine({x+7,y+14},{x+21,y+14},b,1.2f); g.rt->DrawLine({x+14,y+7},{x+14,y+21},b,1.2f); }
    else if(kind==1){ g.rt->DrawRoundedRectangle(D2D1::RoundedRect({x+8,y+6,x+20,y+22},3,3),b,1.5f); g.rt->DrawLine({x+11,y+18},{x+17,y+18},b,1.2f); }
    else { g.rt->DrawEllipse(D2D1::Ellipse({x+10,y+14},3,3),b,1.4f); g.rt->DrawEllipse(D2D1::Ellipse({x+20,y+9},3,3),b,1.4f); g.rt->DrawEllipse(D2D1::Ellipse({x+20,y+19},3,3),b,1.4f); g.rt->DrawLine({x+12.5f,y+12.5f},{x+17.5f,y+10},b,1.2f); g.rt->DrawLine({x+12.5f,y+15.5f},{x+17.5f,y+18},b,1.2f); }
    b->Release();
}

static void LogLine(const std::wstring&s){ g.logs.push_back(L"> ["+NowClock()+L"] "+s); if(g.logs.size()>100) g.logs.erase(g.logs.begin(),g.logs.begin()+20); if(g.hwnd) InvalidateRect(g.hwnd,nullptr,FALSE); }
static void ShowToast(const std::wstring&s){ g.toast=s; g.toastUntil=std::chrono::steady_clock::now()+std::chrono::milliseconds(1700); if(g.hwnd) InvalidateRect(g.hwnd,nullptr,FALSE); }

static void DrawHeader(float W){
    FillRR({0,0,W,68},0,0xFFFFFF); Line(0,67,W,67,0xE6ECF4); DrawBrandIcon(18,12,40); Text(kTitle,{76,10,330,38},g.f20,COL_TEXT); Text(L"检测代理 · 开启共享 · 查看设备",{76,38,360,58},g.f12,COL_MUTED);
    float x=W-480; auto nav=[&](const wchar_t*t,Page p,HitAction a,float w){ bool on=g.page==p; D2D1_RECT_F r{x,17,x+w,51}; if(on) FillRR(r,7,COL_BLUE2); Text(t,{x,x?26.f:26.f,x+w,48},g.f14,on?COL_BLUE:COL_TEXT); AddHit(r,a); x+=w+8; };
    nav(L"手机设置",Page::Phone,HitAction::NavPhone,84); nav(L"接入设备",Page::Devices,HitAction::NavDevices,84); nav(L"高级 / 排障",Page::Advanced,HitAction::NavAdvanced,102);
    Text(std::wstring(L"v")+kVersion,{W-170,26,W-110,48},g.f12,0x8A9AAF);
    D2D1_RECT_F minr{W-92,14,W-52,54}, closer{W-50,14,W-10,54}; Text(L"—",{minr.left,minr.top+8,minr.right,minr.bottom},g.f16,0x68778A); Text(L"×",{closer.left,closer.top+6,closer.right,closer.bottom},g.f20,0x455468); AddHit(minr,HitAction::Minimize); AddHit(closer,HitAction::Close);
}

static void DrawHome(float W,float H){
    D2D1_RECT_F env{22,82,W-22,160}; Card(env); Text(L"当前环境",{40,96,142,124},g.f16,COL_TEXT); Pill({40,126,112,149},g.ip==L"检测中…"?L"检测中":L"环境已就绪",g.ip==L"检测中…"?0xFFF7E6:COL_GREENBG,g.ip==L"检测中…"?0xB7791F:COL_GREEN);
    Line(142,96,142,148,0xE8EEF5); DrawSmallIcon(160,107,0); Text(L"局域网地址",{196,100,300,120},g.f12,COL_MUTED); Text(g.ip,{196,121,340,148},g.f16,COL_TEXT); if(!g.adapter.empty()) Pill({342,121,410,146},g.adapter.find(L"Wi")!=std::wstring::npos?L"Wi-Fi":L"以太网",0xECF8F0,0x17834A);
    Line(430,96,430,148,0xE8EEF5); DrawSmallIcon(448,107,1,0xF4EEFF,0x7C3AED); Text(L"本机代理",{484,100,570,120},g.f12,COL_MUTED); Text(g.process,{484,121,700,143},g.f14,COL_TEXT); if(g.httpLocal) Pill({484,142,558,162},L"HTTP "+std::to_wstring(g.httpLocal),0xEAF2FF,COL_BLUE); if(g.socksLocal) Pill({566,142,662,162},L"SOCKS5 "+std::to_wstring(g.socksLocal),0xF5ECFF,0x7C3AED);
    Button({W-126,104,W-40,142},L"重新检测",HitAction::Rescan,false,g.scanning.load());

    D2D1_RECT_F share{22,174,W-22,406}; Card(share,true); DrawSmallIcon(40,194,2); Text(L"局域网共享",{78,194,220,222},g.f16,COL_TEXT); Text(L"将本机 HTTP 代理开放给同一路由器下的手机、平板和其他设备",{40,226,590,247},g.f12,COL_MUTED);
    Pill({W-164,194,W-64,220},g.sharing?L"● 共享运行中":L"● 未开启",g.sharing?COL_GREENBG:0xF3F5F8,g.sharing?COL_GREEN:0x7E8A99);
    D2D1_RECT_F addr{40,264,W-334,334}; FillRR(addr,8,0xF8FBFF); StrokeRR(addr,8,0xD8E5FA); Text(L"共享地址",{58,277,145,296},g.f12,COL_MUTED); std::wstring shown=(g.ip==L"检测中…"?L"--":g.ip)+L" : "+std::to_wstring(g.httpLan); Text(shown,{58,298,W-440,330},g.f24,COL_TEXT); Pill({W-460,287,W-352,313},L"HTTP 代理",0xEAF2FF,COL_BLUE);
    Button({40,350,150,390},g.sharing?L"开始共享":L"开始共享",HitAction::Start,true,g.sharing); Button({164,350,276,390},L"停止共享",HitAction::Stop,false,!g.sharing); Button({290,350,402,390},L"测试连接",HitAction::Test,false,!g.sharing);
    D2D1_RECT_F summary{W-308,244,W-40,390}; FillRR(summary,9,0xFCFDFE); StrokeRR(summary,9,COL_BORDER); Text(L"共享概览",{W-290,260,W-180,286},g.f14,COL_TEXT); Text(L"接入设备  "+std::to_wstring(g.devices.size())+L" 台在线",{W-290,293,W-90,318},g.f14,COL_TEXT); int act=0; for(auto&d:g.devices)act+=d.active; Text(L"活跃 "+std::to_wstring(act),{W-290,320,W-160,343},g.f13,g.devices.empty()?COL_MUTED:COL_GREEN); Button({W-290,350,W-58,382},L"查看接入设备",HitAction::ViewDevices);

    D2D1_RECT_F logs{22,420,W-22,H-20}; FillRR(logs,9,0x00150B); StrokeRR(logs,9,0x0B492C); Circle(40,441,3,0x22E06F); Text(L"实时运行日志",{52,430,180,455},g.f14,0x36F27C); Button({W-176,430,W-112,462},L"清空",HitAction::ClearLogs); Button({W-106,430,W-40,462},L"复制",HitAction::CopyLogs); Line(38,469,W-38,469,0x0A3C25);
    float y=486; size_t start=g.logs.size()>7?g.logs.size()-7:0; for(size_t i=start;i<g.logs.size() && y<H-30;i++,y+=19) Text(g.logs[i],{38,y,W-38,y+18},g.fMono,0x24F06B);
}

static void DrawBackAndTitle(const std::wstring&title,const std::wstring&sub){ Button({22,82,112,118},L"← 返回主页",HitAction::Back); Text(title,{128,80,530,111},g.f20,COL_TEXT); Text(sub,{128,111,650,132},g.f12,COL_MUTED); }

static void DrawPhone(float W,float H){
    DrawBackAndTitle(L"手机设置向导",L"首次连接时配置一次；之后在同一 Wi-Fi 下通常无需重复填写。");
    Button({W-220,82,W-122,118},L"安卓通用",HitAction::Android,!g.ios,false); Button({W-116,82,W-22,118},L"iPhone / iPad",HitAction::IOS,g.ios,false);
    D2D1_RECT_F left{22,134,W-322,H-44}, right{W-302,134,W-22,370}; Card(left); Card(right,true); Text(g.ios?L"iPhone / iPad 设置":L"安卓通用设置",{44,153,360,185},g.f16,COL_TEXT);
    struct Step{const wchar_t*t; const wchar_t*s;}; Step a[]={{L"打开 Wi-Fi 设置",L"设置 → WLAN / Wi-Fi"},{L"进入当前网络详情",g.ios?L"点击已连接 Wi-Fi 右侧的信息按钮":L"点击当前网络；部分机型也可长按当前 Wi-Fi → 修改网络"},{L"把代理设为“手动”",g.ios?L"配置代理 → 手动":L"高级选项 / 代理 → 手动"},{L"填写服务器和端口",L"填写右侧当前共享地址，保存后即可使用"}};
    float y=198; for(int i=0;i<4;i++){ Circle(68,y+18,13,COL_BLUE); Text(std::to_wstring(i+1),{55,y+9,81,y+30},g.f13,0xFFFFFF); if(i<3) Line(68,y+31,68,y+63,0xBFD2F5,1.2f); Text(a[i].t,{96,y,400,y+23},g.f14,COL_TEXT); Text(a[i].s,{96,y+27,W-352,y+48},g.f12,COL_MUTED); if(i<3) Line(96,y+56,W-346,y+56,0xE8EEF5); y+=68; }
    FillRR({44,480,W-344,530},7,0xF8FAFD); Text(L"ⓘ 不同安卓品牌入口名称略有差异，核心是找到当前 Wi-Fi 的“代理”设置并选择“手动”。",{58,494,W-360,522},g.f12,COL_MUTED);
    Text(L"当前需要填写",{W-282,154,W-100,184},g.f16,COL_TEXT); Pill({W-142,151,W-42,177},L"HTTP 手动代理",0xEAF2FF,COL_BLUE); Text(L"服务器",{W-282,197,W-160,217},g.f12,COL_MUTED); Text(g.ip,{W-282,221,W-60,254},g.f24,COL_TEXT); Line(W-282,262,W-42,262,0xDDE6F0); Text(L"端口",{W-282,278,W-160,298},g.f12,COL_MUTED); Text(std::to_wstring(g.httpLan),{W-282,301,W-100,338},g.f24,COL_BLUE); Text(L"手机与电脑需连接到同一个可互访的 Wi-Fi / 路由器。",{W-282,342,W-42,366},g.f12,COL_MUTED);
}

static void DrawDevices(float W,float H){
    DrawBackAndTitle(L"接入设备",L"只统计真实连接到本机共享端口的局域网设备。");
    Text(g.lastSync.empty()?L"":L"● 已同步 · "+g.lastSync,{W-196,90,W-84,113},g.f12,COL_GREEN); Button({W-80,82,W-22,118},L"刷新",HitAction::RefreshDevices,false,g.deviceScan.load());
    D2D1_RECT_F s1{22,138,(W-44)/3,208},s2{(W-44)/3+12,138,2*(W-44)/3-2,208},s3{2*(W-44)/3+10,138,W-22,208}; Card(s1);Card(s2);Card(s3); Text(L"在线设备",{40,152,150,172},g.f12,COL_MUTED); Text(std::to_wstring(g.devices.size()),{40,175,160,202},g.f24,COL_TEXT); int active=0;for(auto&d:g.devices)active+=d.active; Text(L"活跃",{s2.left+18,152,s2.right-20,172},g.f12,COL_MUTED); Text(std::to_wstring(active),{s2.left+18,175,s2.right-20,202},g.f24,active?COL_GREEN:COL_MUTED); Text(L"当前共享地址",{s3.left+18,152,s3.right-20,172},g.f12,COL_MUTED); Text(g.ip+L":"+std::to_wstring(g.httpLan),{s3.left+18,176,s3.right-20,202},g.f16,COL_BLUE);
    D2D1_RECT_F list{22,220,W-22,H-44}; Card(list); if(g.devices.empty()){ Text(L"暂无设备接入",{22,250,W-22,280},g.f16,COL_TEXT); Text(L"开启共享后，当手机开始通过手动代理访问网络时，会自动显示在这里。",{22,288,W-22,315},g.f13,COL_MUTED); }
    else { float y=242; for(auto&d:g.devices){ DrawSmallIcon(44,y+10,1); Text(d.ip,{82,y+8,250,y+31},g.f14,COL_TEXT); Text(L"局域网设备",{82,y+34,250,y+54},g.f12,COL_MUTED); Text(L"在线 · 活跃 "+std::to_wstring(d.active),{330,y+8,490,y+31},g.f14,COL_GREEN); Text(L"HTTP "+std::to_wstring(g.httpLan),{330,y+34,490,y+54},g.f12,COL_MUTED); Text(L"MAC："+(d.mac.empty()?L"—":d.mac),{W-320,y+8,W-60,y+28},g.f12,COL_MUTED); Text(L"首次接入："+d.firstSeen,{W-320,y+31,W-60,y+51},g.f12,COL_MUTED); Text(L"最近活动：刚刚",{W-320,y+52,W-60,y+72},g.f12,COL_MUTED); Line(44,y+86,W-44,y+86,0xE8EEF5); y+=96; if(y>H-120)break; } }
}

static void UpdateEditVisibility();
static void DrawAdvanced(float W,float H){
    DrawBackAndTitle(L"高级设置与故障排查",L"正常使用无需修改；只有自动检测失败、端口冲突或需要 SOCKS5 时再调整。");
    D2D1_RECT_F left{22,140,W-328,H-50}, top{W-308,140,W-22,384}, bottom{W-308,398,W-22,H-50}; Card(left);Card(top);Card(bottom); Text(L"端口设置",{44,158,200,185},g.f16,COL_TEXT); Text(L"自动检测正常时不建议手动修改。局域网 HTTP 端口就是手机需要填写的端口。",{44,188,W-350,210},g.f12,COL_MUTED);
    Text(L"本机 HTTP",{54,226,180,248},g.f14,COL_TEXT); Text(L"代理软件在电脑本地监听的 HTTP 端口",{54,249,300,269},g.f12,COL_MUTED); Text(L"本机 SOCKS5",{358,226,520,248},g.f14,COL_TEXT); Text(L"代理软件在电脑本地监听的 SOCKS5 端口",{358,249,W-350,269},g.f12,COL_MUTED); Text(L"局域网 HTTP",{54,330,180,352},g.f14,COL_TEXT); Text(L"手机 / 平板默认填写这个共享端口",{54,353,300,373},g.f12,COL_MUTED); Text(L"局域网 SOCKS5",{358,330,520,352},g.f14,COL_TEXT); Text(L"高级用户可选，普通手机代理不需要",{358,353,W-350,373},g.f12,COL_MUTED);
    Text(L"同时共享 SOCKS5",{405,444,560,466},g.f14,COL_TEXT); D2D1_RECT_F sw{358,438,398,462}; FillRR(sw,12,g.shareSocks?COL_BLUE:0xD7DFEA); Circle(g.shareSocks?386:370,450,8,0xFFFFFF); AddHit(sw,HitAction::ToggleSocks);
    FillRR({44,478,W-350,538},7,0xF8FAFD); Text(L"ⓘ 建议",{58,491,120,512},g.f13,COL_TEXT); Text(L"自动检测已经识别出本机代理时，请优先保留检测到的端口。修改后会自动保存。",{58,515,W-366,535},g.f12,COL_MUTED);
    Text(L"快速排障",{W-286,158,W-130,184},g.f16,COL_TEXT); Text(L"遇到无法共享时，按下面顺序检查通常最快。",{W-286,188,W-42,210},g.f12,COL_MUTED); auto row=[&](float y,int n,const wchar_t*t,const wchar_t*s,HitAction a){ FillRR({W-286,y,W-44,y+50},7,0xFBFCFE);StrokeRR({W-286,y,W-44,y+50},7,COL_BORDER); Circle(W-268,y+25,10,0xEAF2FF);Text(std::to_wstring(n),{W-278,y+16,W-258,y+36},g.f12,COL_BLUE);Text(t,{W-248,y+8,W-76,y+27},g.f13,COL_TEXT);Text(s,{W-248,y+28,W-76,y+45},g.f12,COL_MUTED);Text(L">",{W-64,y+15,W-48,y+35},g.f14,0x9BA8B8);AddHit({W-286,y,W-44,y+50},a);}; row(220,1,L"重新检测网络与代理",L"确认 IP 和代理端口都已识别",HitAction::Rescan);row(278,2,L"测试共享端口",L"检查本机共享端口是否可访问",HitAction::Test);row(336,3,L"恢复默认共享端口",L"HTTP 18800 · SOCKS5 11020",HitAction::ResetPorts);
    Text(L"常见原因",{W-286,418,W-150,444},g.f16,COL_TEXT); Text(L"• 手机和电脑不在同一个可互访的局域网。\n• 公司 / 访客 Wi-Fi 或 AP 隔离阻止设备互访。\n• Windows 防火墙阻止了本程序的入站连接。\n• 代理软件没有监听本机 HTTP 端口。",{W-286,454,W-42,H-74},g.f12,COL_MUTED);
}

static void EnsureRenderTarget(){ if(g.rt)return; RECT rc{};GetClientRect(g.hwnd,&rc); g.d2d->CreateHwndRenderTarget(D2D1::RenderTargetProperties(),D2D1::HwndRenderTargetProperties(g.hwnd,D2D1::SizeU(rc.right,rc.bottom)),&g.rt); }
static void Render(){ EnsureRenderTarget(); if(!g.rt)return; RECT rc{};GetClientRect(g.hwnd,&rc); float W=(float)rc.right,H=(float)rc.bottom; g.hits.clear(); g.rt->BeginDraw(); g.rt->Clear(C(COL_BG)); DrawHeader(W); if(g.page==Page::Home)DrawHome(W,H); else if(g.page==Page::Phone)DrawPhone(W,H); else if(g.page==Page::Devices)DrawDevices(W,H); else DrawAdvanced(W,H); if(!g.toast.empty()&&std::chrono::steady_clock::now()<g.toastUntil){ D2D1_RECT_F r{W-390,74,W-28,112}; FillRR(r,8,0xFFFFFF);StrokeRR(r,8,0xCFE0F6);Circle(r.left+18,r.top+19,5,COL_GREEN);Text(g.toast,{r.left+32,r.top+9,r.right-12,r.bottom-8},g.f13,COL_TEXT); } HRESULT hr=g.rt->EndDraw(); if(hr==D2DERR_RECREATE_TARGET)SafeRelease(g.rt); }

static std::wstring ConfigDir(){ PWSTR p=nullptr; std::wstring d; if(SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData,0,nullptr,&p))){ d=p;CoTaskMemFree(p); d+=L"\\LANProxyShareAssistant"; CreateDirectoryW(d.c_str(),nullptr);} return d; }
static void SaveConfig(){ std::wstring p=ConfigDir()+L"\\config.ini"; std::wofstream f(p); if(f){f<<g.httpLocal<<L"\n"<<g.socksLocal<<L"\n"<<g.httpLan<<L"\n"<<g.socksLan<<L"\n"<<(g.shareSocks?1:0)<<L"\n";} }
static void LoadConfig(){ std::wstring p=ConfigDir()+L"\\config.ini"; std::wifstream f(p); int b=0; if(f>>g.httpLocal>>g.socksLocal>>g.httpLan>>g.socksLan>>b){g.shareSocks=b!=0;} if(g.httpLan<=0)g.httpLan=18800;if(g.socksLan<=0)g.socksLan=11020; }

static void StartScan(){ if(g.scanning.exchange(true))return; g.process=L"正在检测"; ShowToast(L"正在重新检测局域网与本机代理…"); std::thread([]{ auto*r=new ScanResult(DetectEnvironment()); PostMessageW(g.hwnd,WM_APP_SCAN_DONE,0,(LPARAM)r); }).detach(); }
static void StartDeviceScan(){ if(g.deviceScan.exchange(true))return; int port=g.httpLan; std::thread([port]{ auto*v=new std::vector<DeviceInfo>(EnumerateDevices(port)); PostMessageW(g.hwnd,WM_APP_DEVICES_DONE,0,(LPARAM)v); }).detach(); }

struct ActionResult{ int kind=0; bool ok=false; std::wstring msg; };
static void DoAction(int kind){ std::thread([kind]{ auto*r=new ActionResult(); r->kind=kind; if(kind==1){ if(g.ip.empty()||g.ip==L"检测中…"||g.httpLocal<=0){r->msg=L"未检测到可用的局域网或 HTTP 代理";} else { g.httpRelay.Stop();g.socksRelay.Stop(); bool ok=g.httpRelay.Start(g.ip,g.httpLan,g.httpLocal); if(ok&&g.shareSocks&&g.socksLocal>0)g.socksRelay.Start(g.ip,g.socksLan,g.socksLocal); r->ok=ok; r->msg=ok?L"共享已开启 · "+g.ip+L":"+std::to_wstring(g.httpLan):L"共享端口启动失败"; }} else if(kind==2){g.httpRelay.Stop();g.socksRelay.Stop();r->ok=true;r->msg=L"共享已停止";} else if(kind==3){ SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);SetSocketTimeout(s,900);sockaddr_in sa{};sa.sin_family=AF_INET;sa.sin_port=htons((u_short)g.httpLan);InetPtonW(AF_INET,g.ip.c_str(),&sa.sin_addr);r->ok=s!=INVALID_SOCKET&&connect(s,(sockaddr*)&sa,sizeof(sa))==0;if(s!=INVALID_SOCKET)closesocket(s);r->msg=r->ok?L"测试通过：共享端口可访问":L"测试未通过：共享端口暂不可访问";} PostMessageW(g.hwnd,WM_APP_ACTION_DONE,0,(LPARAM)r); }).detach(); }

static void CopyText(const std::wstring&s){ if(!OpenClipboard(g.hwnd))return;EmptyClipboard();SIZE_T n=(s.size()+1)*sizeof(wchar_t);HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE,n);if(h){memcpy(GlobalLock(h),s.c_str(),n);GlobalUnlock(h);SetClipboardData(CF_UNICODETEXT,h);}CloseClipboard(); }
static void UpdateEditVisibility(){ bool show=g.page==Page::Advanced; for(auto h:g.edits)ShowWindow(h,show?SW_SHOW:SW_HIDE); if(show){ RECT rc{};GetClientRect(g.hwnd,&rc); int W=rc.right; MoveWindow(g.edits[0],54,276,260,34,TRUE);MoveWindow(g.edits[1],358,276,260,34,TRUE);MoveWindow(g.edits[2],54,380,260,34,TRUE);MoveWindow(g.edits[3],358,380,260,34,TRUE); wchar_t b[32]{};int vals[]={g.httpLocal,g.socksLocal,g.httpLan,g.socksLan};for(int i=0;i<4;i++){swprintf_s(b,L"%d",vals[i]);SetWindowTextW(g.edits[i],b);} } }
static void ReadEdits(){ if(g.page!=Page::Advanced)return; int* vals[]={&g.httpLocal,&g.socksLocal,&g.httpLan,&g.socksLan}; wchar_t b[32]{}; for(int i=0;i<4;i++){GetWindowTextW(g.edits[i],b,32);int v=_wtoi(b); if(v>=0&&v<=65535)*vals[i]=v;} SaveConfig(); }

static void HandleHit(HitAction a){
    switch(a){
    case HitAction::NavPhone:g.page=Page::Phone;break;case HitAction::NavDevices:g.page=Page::Devices;StartDeviceScan();break;case HitAction::NavAdvanced:g.page=Page::Advanced;break;case HitAction::Back:g.page=Page::Home;break;
    case HitAction::Rescan:StartScan();break;case HitAction::Start:DoAction(1);break;case HitAction::Stop:DoAction(2);break;case HitAction::Test:DoAction(3);break;case HitAction::ViewDevices:g.page=Page::Devices;StartDeviceScan();break;
    case HitAction::Android:g.ios=false;break;case HitAction::IOS:g.ios=true;break;case HitAction::RefreshDevices:StartDeviceScan();break;case HitAction::ClearLogs:g.logs.clear();break;case HitAction::CopyLogs:{std::wstring s;for(auto&l:g.logs)s+=l+L"\r\n";CopyText(s);ShowToast(L"日志已复制");}break;
    case HitAction::ResetPorts:g.httpLan=18800;g.socksLan=11020;SaveConfig();UpdateEditVisibility();ShowToast(L"共享端口已恢复默认值");break;case HitAction::ToggleSocks:g.shareSocks=!g.shareSocks;SaveConfig();break;case HitAction::Minimize:ShowWindow(g.hwnd,SW_MINIMIZE);return;case HitAction::Close:PostMessageW(g.hwnd,WM_CLOSE,0,0);return;default:break; }
    UpdateEditVisibility();InvalidateRect(g.hwnd,nullptr,FALSE);
}

static void InitFonts(){ auto mk=[&](float sz,DWRITE_FONT_WEIGHT w,const wchar_t*family,IDWriteTextFormat**out){ g.dw->CreateTextFormat(family,nullptr,w,DWRITE_FONT_STYLE_NORMAL,DWRITE_FONT_STRETCH_NORMAL,sz,L"zh-CN",out);(*out)->SetTextAlignment(DWRITE_TEXT_ALIGNMENT_LEADING);(*out)->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_NEAR);}; mk(12,DWRITE_FONT_WEIGHT_NORMAL,L"Microsoft YaHei UI",&g.f12);mk(13,DWRITE_FONT_WEIGHT_NORMAL,L"Microsoft YaHei UI",&g.f13);mk(14,DWRITE_FONT_WEIGHT_SEMI_BOLD,L"Microsoft YaHei UI",&g.f14);mk(16,DWRITE_FONT_WEIGHT_SEMI_BOLD,L"Microsoft YaHei UI",&g.f16);mk(20,DWRITE_FONT_WEIGHT_SEMI_BOLD,L"Microsoft YaHei UI",&g.f20);mk(24,DWRITE_FONT_WEIGHT_SEMI_BOLD,L"Microsoft YaHei UI",&g.f24);mk(12,DWRITE_FONT_WEIGHT_NORMAL,L"Cascadia Mono",&g.fMono); }

static LRESULT CALLBACK WndProc(HWND h,UINT m,WPARAM w,LPARAM l){
    switch(m){
    case WM_CREATE:{ g.hwnd=h; D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED,&g.d2d);DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED,__uuidof(IDWriteFactory),(IUnknown**)&g.dw);InitFonts();g.editFont=CreateFontW(-15,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");for(int i=0;i<4;i++){g.edits[i]=CreateWindowExW(0,L"EDIT",L"0",WS_CHILD|WS_BORDER|ES_CENTER|ES_NUMBER,0,0,0,0,h,(HMENU)(100+i),GetModuleHandleW(nullptr),nullptr);SendMessageW(g.edits[i],WM_SETFONT,(WPARAM)g.editFont,TRUE);}LoadConfig();SetTimer(h,TIMER_ID,1000,nullptr);LogLine(L"程序已启动");StartScan();return 0;}
    case WM_SIZE: if(g.rt)g.rt->Resize(D2D1::SizeU(LOWORD(l),HIWORD(l)));InvalidateRect(h,nullptr,FALSE);return 0;
    case WM_PAINT:{PAINTSTRUCT ps{};BeginPaint(h,&ps);Render();EndPaint(h,&ps);return 0;}
    case WM_ERASEBKGND:return 1;
    case WM_TIMER: if(w==TIMER_ID){ if(g.sharing)StartDeviceScan(); if(!g.toast.empty()&&std::chrono::steady_clock::now()>=g.toastUntil){g.toast.clear();InvalidateRect(h,nullptr,FALSE);} }return 0;
    case WM_COMMAND: if(HIWORD(w)==EN_KILLFOCUS){ReadEdits();InvalidateRect(h,nullptr,FALSE);}return 0;
    case WM_LBUTTONUP:{ float x=(float)GET_X_LPARAM(l),y=(float)GET_Y_LPARAM(l); for(auto&hit:g.hits)if(x>=hit.r.left&&x<=hit.r.right&&y>=hit.r.top&&y<=hit.r.bottom){HandleHit(hit.a);return 0;} return 0; }
    case WM_LBUTTONDOWN:{ float x=(float)GET_X_LPARAM(l),y=(float)GET_Y_LPARAM(l); bool onHit=false;for(auto&hit:g.hits)if(x>=hit.r.left&&x<=hit.r.right&&y>=hit.r.top&&y<=hit.r.bottom){onHit=true;break;} if(y<68&&!onHit){ReleaseCapture();SendMessageW(h,WM_NCLBUTTONDOWN,HTCAPTION,0);}return 0;}
    case WM_APP_SCAN_DONE:{std::unique_ptr<ScanResult>r((ScanResult*)l);g.scanning=false;if(!r->ip.empty())g.ip=r->ip;if(!r->adapter.empty())g.adapter=r->adapter;if(!r->process.empty())g.process=r->process;else g.process=L"未检测到可用代理";if(r->httpPort)g.httpLocal=r->httpPort;if(r->socksPort)g.socksLocal=r->socksPort;LogLine(L"局域网地址："+g.ip);if(g.httpLocal||g.socksLocal)LogLine(L"检测到代理进程 "+g.process+L"：HTTP "+std::to_wstring(g.httpLocal)+L"，SOCKS5 "+std::to_wstring(g.socksLocal));ShowToast(L"检测完成");SaveConfig();UpdateEditVisibility();InvalidateRect(h,nullptr,FALSE);return 0;}
    case WM_APP_ACTION_DONE:{std::unique_ptr<ActionResult>r((ActionResult*)l);if(r->kind==1&&r->ok){g.sharing=true;g.shareStart=std::chrono::steady_clock::now();LogLine(L"共享已开启：http://"+g.ip+L":"+std::to_wstring(g.httpLan));StartDeviceScan();}else if(r->kind==2&&r->ok){g.sharing=false;g.devices.clear();LogLine(L"共享已停止");}else if(r->kind==3)LogLine(r->msg);ShowToast(r->msg);InvalidateRect(h,nullptr,FALSE);return 0;}
    case WM_APP_DEVICES_DONE:{std::unique_ptr<std::vector<DeviceInfo>>v((std::vector<DeviceInfo>*)l);g.deviceScan=false;g.devices=*v;g.lastSync=NowClock();InvalidateRect(h,nullptr,FALSE);return 0;}
    case WM_CLOSE:g.httpRelay.Stop();g.socksRelay.Stop();DestroyWindow(h);return 0;
    case WM_DESTROY:KillTimer(h,TIMER_ID);SafeRelease(g.rt);SafeRelease(g.d2d);SafeRelease(g.f12);SafeRelease(g.f13);SafeRelease(g.f14);SafeRelease(g.f16);SafeRelease(g.f20);SafeRelease(g.f24);SafeRelease(g.fMono);SafeRelease(g.dw);if(g.editFont)DeleteObject(g.editFont);PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(h,m,w,l);
}

int WINAPI wWinMain(HINSTANCE hi,HINSTANCE,LPWSTR,int){
    CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED); WSADATA wd{}; if(WSAStartup(MAKEWORD(2,2),&wd)!=0)return 1;
    WNDCLASSEXW wc{sizeof(wc)};wc.style=CS_HREDRAW|CS_VREDRAW;wc.lpfnWndProc=WndProc;wc.hInstance=hi;wc.hCursor=LoadCursor(nullptr,IDC_ARROW);wc.hIcon=LoadIcon(hi,MAKEINTRESOURCE(101));wc.hIconSm=LoadIcon(hi,MAKEINTRESOURCE(101));wc.lpszClassName=kClassName;RegisterClassExW(&wc);
    RECT r{0,0,960,620};AdjustWindowRectEx(&r,WS_POPUP|WS_SYSMENU|WS_MINIMIZEBOX,FALSE,0);int sw=GetSystemMetrics(SM_CXSCREEN),sh=GetSystemMetrics(SM_CYSCREEN);int ww=r.right-r.left,hh=r.bottom-r.top;HWND h=CreateWindowExW(0,kClassName,kTitle,WS_POPUP|WS_SYSMENU|WS_MINIMIZEBOX,(sw-ww)/2,(sh-hh)/2,ww,hh,nullptr,nullptr,hi,nullptr);if(!h)return 2;ShowWindow(h,SW_SHOW);UpdateWindow(h);MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}WSACleanup();CoUninitialize();return (int)msg.wParam;
}

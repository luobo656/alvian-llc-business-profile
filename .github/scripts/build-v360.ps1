$ErrorActionPreference = 'Stop'

$src = '.\lanproxy-native-v360\src'
New-Item -ItemType Directory -Path $src -Force | Out-Null
$chunkNames = @('source.chunk00x','source.chunk01','source.chunk02','source.chunk03','source.chunk04','source.chunk05','source.chunk06','source.chunk07','source.chunk08')
$segments = @()
foreach($n in $chunkNames){ $segments += (Get-Content (Join-Path '.\lanproxy-native-v330' $n) -Raw).Trim() }
$all = $segments -join ''
if($all.Length -ne 34880){ throw "Unexpected source payload length: $($all.Length)" }
[IO.File]::WriteAllBytes((Join-Path $src 'main.go.gz'), [Convert]::FromBase64String($all))
$in=[IO.File]::OpenRead((Resolve-Path (Join-Path $src 'main.go.gz')))
try {
  $gz=New-Object IO.Compression.GzipStream($in,[IO.Compression.CompressionMode]::Decompress)
  try {
    $out=[IO.File]::Create((Join-Path (Resolve-Path $src) 'main.go'))
    try{$gz.CopyTo($out)}finally{$out.Dispose()}
  } finally{$gz.Dispose()}
} finally{$in.Dispose()}

$main = Join-Path $src 'main.go'
$text = [IO.File]::ReadAllText((Resolve-Path $main)).Replace("`r`n","`n")
if(-not $text.Contains('appVersion = "3.3.0"')){ throw 'Expected v3.3 version marker not found' }
$text = $text.Replace('appVersion = "3.3.0"','appVersion = "3.6.0"')
if(-not $text.Contains('1080, 600, 0, 0, hInst, 0)')){ throw 'Expected v3.3 window size not found' }
$text = $text.Replace('1080, 600, 0, 0, hInst, 0)','960, 620, 0, 0, hInst, 0)')

# Keep the same compact share-logo used by the current UI.
$logoStart = $text.IndexOf('func drawWifi(hdc syscall.Handle, x, y int32) {')
if($logoStart -lt 0){ throw 'drawWifi start not found' }
$logoEnd = $text.IndexOf("`n}", $logoStart)
if($logoEnd -lt 0){ throw 'drawWifi end not found' }
$logoEnd += 2
$newLogo = @'
func drawWifi(hdc syscall.Handle, x, y int32) {
	blue := rgb(37, 99, 235)
	white := rgb(255, 255, 255)
	fillRounded(hdc, RECT{x, y, x + 38, y + 38}, 10, blue)
	line(hdc, x+14, y+19, x+24, y+12, white, 2)
	line(hdc, x+14, y+19, x+24, y+26, white, 2)
	circle(hdc, x+11, y+19, 4, white, white)
	circle(hdc, x+27, y+10, 4, white, white)
	circle(hdc, x+27, y+28, 4, white, white)
}
'@
$text = $text.Substring(0,$logoStart) + $newLogo.TrimEnd() + $text.Substring($logoEnd)

if(-not $text.Contains("`n`t`"io`"`n")){
  $text = $text.Replace("`n`t`"fmt`"`n", "`n`t`"fmt`"`n`t`"io`"`n")
}

# Keep process name recognition useful without administrator rights.
$procStart = $text.IndexOf('func processName(pid int) string {')
$procEnd = $text.IndexOf('func dialLocal(', $procStart)
if($procStart -lt 0 -or $procEnd -lt 0){ throw 'processName block not found' }
$newProc = @'
func processName(pid int) string {
	h, _, _ := pOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION, 0, uintptr(pid))
	if h != 0 {
		buf := make([]uint16, 32768)
		size := uint32(len(buf))
		r, _, _ := pQueryFullProcessImageNameW.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		pCloseHandle.Call(h)
		if r != 0 {
			if b := filepath.Base(syscall.UTF16ToString(buf[:size])); b != "" { return b }
		}
	}
	out, err := runHidden("tasklist.exe", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	if err == nil {
		line := strings.TrimSpace(strings.Split(out, "\n")[0])
		if strings.HasPrefix(line, "\"") {
			if i := strings.Index(line[1:], "\""); i >= 0 {
				name := strings.TrimSpace(line[1 : i+1])
				if name != "" { return name }
			}
		}
	}
	return fmt.Sprintf("PID %d", pid)
}

'@
$text = $text.Substring(0,$procStart) + $newProc + $text.Substring($procEnd)

# In-process TCP relay replaces persistent netsh portproxy rules.
$captureMarker = 'func captureShareParams() shareParams {'
$capturePos = $text.IndexOf($captureMarker)
if($capturePos -lt 0){ throw 'captureShareParams marker not found' }
$relayCode = @'
type relayServer struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
}

var relayState struct {
	sync.Mutex
	servers []*relayServer
}

func newRelay(listenIP string, listenPort, targetPort int) (*relayServer, error) {
	ln, err := net.Listen("tcp4", net.JoinHostPort(listenIP, strconv.Itoa(listenPort)))
	if err != nil { return nil, err }
	r := &relayServer{ln: ln, target: net.JoinHostPort("127.0.0.1", strconv.Itoa(targetPort)), conns: map[net.Conn]struct{}{}}
	go r.serve()
	return r, nil
}

func (r *relayServer) serve() {
	for {
		client, err := r.ln.Accept()
		if err != nil { return }
		go r.bridge(client)
	}
}

func (r *relayServer) track(c net.Conn, add bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if add { r.conns[c] = struct{}{} } else { delete(r.conns, c) }
}

func (r *relayServer) bridge(client net.Conn) {
	r.track(client, true)
	defer func(){ r.track(client, false); client.Close() }()
	upstream, err := net.DialTimeout("tcp4", r.target, 2*time.Second)
	if err != nil { return }
	r.track(upstream, true)
	defer func(){ r.track(upstream, false); upstream.Close() }()
	done := make(chan struct{}, 1)
	go func(){ _, _ = io.Copy(upstream, client); if tcp, ok := upstream.(*net.TCPConn); ok { _ = tcp.CloseWrite() }; done <- struct{}{} }()
	_, _ = io.Copy(client, upstream)
	<-done
}

func (r *relayServer) close() {
	if r == nil { return }
	_ = r.ln.Close()
	r.mu.Lock()
	for c := range r.conns { _ = c.Close() }
	r.conns = map[net.Conn]struct{}{}
	r.mu.Unlock()
}

func replaceRelays(servers []*relayServer) {
	relayState.Lock()
	old := relayState.servers
	relayState.servers = servers
	relayState.Unlock()
	for _, r := range old { r.close() }
}

func stopRelays() { replaceRelays(nil) }

'@
$text = $text.Substring(0,$capturePos) + $relayCode + $text.Substring($capturePos)

$actionStart = $text.IndexOf('func runShareAction(action int, p shareParams) actionResult {')
$actionEnd = $text.IndexOf('func applyActionResult()', $actionStart)
if($actionStart -lt 0 -or $actionEnd -lt 0){ throw 'runShareAction block not found' }
$newAction = @'
func runShareAction(action int, p shareParams) actionResult {
	res := actionResult{Action: action}
	switch action {
	case actEnable:
		if p.IP == "" { res.Toast = "未检测到可用局域网，请先重新检测"; res.Logs = append(res.Logs, "开启共享失败：未检测到局域网 IP。"); return res }
		if p.HTTPLocal == 0 { res.Toast = "未检测到本机 HTTP 代理端口"; res.Logs = append(res.Logs, "开启共享失败：本机 HTTP 代理端口无效。"); return res }
		if c, err := dialLocal(p.HTTPLocal, 350*time.Millisecond); err != nil { res.Toast = fmt.Sprintf("本机 HTTP %d 暂不可用", p.HTTPLocal); res.Logs = append(res.Logs, fmt.Sprintf("开启共享失败：本机 HTTP %d 无法连接。", p.HTTPLocal)); return res } else { c.Close() }
		if p.HTTPLAN == 0 { res.Toast = "共享端口无效"; res.Logs = append(res.Logs, "开启共享失败：局域网 HTTP 共享端口无效。"); return res }
		stopRelays()
		res.Logs = append(res.Logs, "正在启动 HTTP 局域网转发…")
		httpRelay, err := newRelay(p.IP, p.HTTPLAN, p.HTTPLocal)
		if err != nil { res.Toast = "HTTP 共享端口启动失败"; res.Logs = append(res.Logs, "HTTP 共享端口启动失败："+err.Error()); return res }
		servers := []*relayServer{httpRelay}
		if p.ShareSOCKS && p.SOCKSLocal > 0 && p.SOCKSLAN > 0 {
			if socksRelay, err := newRelay(p.IP, p.SOCKSLAN, p.SOCKSLocal); err == nil { servers = append(servers, socksRelay); res.Logs = append(res.Logs, "SOCKS5 局域网转发已启动。") } else { res.Logs = append(res.Logs, "SOCKS5 共享启动失败："+err.Error()) }
		}
		relayState.Lock(); relayState.servers = servers; relayState.Unlock()
		res.OK = true; res.SetShareState = true; res.ShareState = true
		res.Toast = fmt.Sprintf("共享已开启 · %s:%d", p.IP, p.HTTPLAN)
		res.Logs = append(res.Logs, fmt.Sprintf("共享已开启：http://%s:%d", p.IP, p.HTTPLAN))
		return res
	case actDisable:
		stopRelays()
		res.OK = true; res.SetShareState = true; res.ShareState = false; res.Toast = "共享已停止"
		res.Logs = append(res.Logs, "已停止本工具的局域网转发。")
		return res
	case actTest:
		if p.IP == "" || p.HTTPLAN == 0 { res.Toast = "当前没有有效的共享地址"; return res }
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("%s:%d", p.IP, p.HTTPLAN), 900*time.Millisecond)
		if err != nil { res.Toast = "测试未通过：共享端口暂不可访问"; res.Logs = append(res.Logs, "共享端口测试失败："+err.Error()); return res }
		c.Close(); res.OK = true; res.Toast = "测试通过：电脑端共享端口可访问"; res.Logs = append(res.Logs, "共享端口测试通过。"); return res
	}
	return res
}

'@
$text = $text.Substring(0,$actionStart) + $newAction + $text.Substring($actionEnd)

# Standard-user startup. The live sharing path no longer modifies persistent system portproxy rules.
$mainPos = $text.IndexOf('func main() {')
$adminStart = $text.IndexOf("`n`tif !isAdmin() {", $mainPos)
$initPos = $text.IndexOf("`n`tinitConfig()", $adminStart)
if($adminStart -lt 0 -or $initPos -lt 0){ throw 'startup elevation block not found' }
$text = $text.Substring(0,$adminStart) + "`n`t// Standard-user startup: no persistent system portproxy rules.`n" + $text.Substring($initPos)

[IO.File]::WriteAllText((Resolve-Path $main), $text, [Text.UTF8Encoding]::new($false))
Copy-Item '.\lanproxy-native-v310\go.mod' (Join-Path $src 'go.mod') -Force
$manifest = [IO.File]::ReadAllText((Resolve-Path '.\lanproxy-native-v310\app.manifest')).Replace('3.1.0.0','3.6.0.0').Replace('level="requireAdministrator"','level="asInvoker"')
[IO.File]::WriteAllText((Join-Path (Resolve-Path $src) 'app.manifest'), $manifest, [Text.UTF8Encoding]::new($false))
gofmt -w $main

# Generate the same current multi-size icon.
Add-Type -AssemblyName System.Drawing
function New-RoundPath([float]$x,[float]$y,[float]$w,[float]$h,[float]$r){ $p=[Drawing.Drawing2D.GraphicsPath]::new(); $d=$r*2; $p.AddArc($x,$y,$d,$d,180,90); $p.AddArc($x+$w-$d,$y,$d,$d,270,90); $p.AddArc($x+$w-$d,$y+$h-$d,$d,$d,0,90); $p.AddArc($x,$y+$h-$d,$d,$d,90,90); $p.CloseFigure(); return $p }
function Render-Logo([int]$s){
  $bmp=[Drawing.Bitmap]::new($s,$s,[Drawing.Imaging.PixelFormat]::Format32bppArgb); $g=[Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias; $g.PixelOffsetMode=[Drawing.Drawing2D.PixelOffsetMode]::HighQuality; $g.Clear([Drawing.Color]::Transparent)
  $pad=[float]($s*0.045); $rect=[Drawing.RectangleF]::new($pad,$pad,$s-2*$pad,$s-2*$pad); $path=New-RoundPath $rect.X $rect.Y $rect.Width $rect.Height ([float]($s*0.205)); $grad=[Drawing.Drawing2D.LinearGradientBrush]::new($rect,[Drawing.Color]::FromArgb(255,37,99,235),[Drawing.Color]::FromArgb(255,59,130,246),55.0); $g.FillPath($grad,$path)
  $white=[Drawing.Color]::White; $pen=[Drawing.Pen]::new($white,[Math]::Max(1.5,$s*0.052)); $pen.StartCap=[Drawing.Drawing2D.LineCap]::Round; $pen.EndCap=[Drawing.Drawing2D.LineCap]::Round
  $x1=[float]($s*0.34); $y1=[float]($s*0.50); $x2=[float]($s*0.66); $y2=[float]($s*0.31); $x3=[float]($s*0.66); $y3=[float]($s*0.69); $g.DrawLine($pen,$x1,$y1,$x2,$y2); $g.DrawLine($pen,$x1,$y1,$x3,$y3)
  $brush=[Drawing.SolidBrush]::new($white); $r=[float]([Math]::Max(1.8,$s*0.072)); foreach($pt in @(@($x1,$y1),@($x2,$y2),@($x3,$y3))){ $g.FillEllipse($brush,[float]$pt[0]-$r,[float]$pt[1]-$r,$r*2,$r*2) }
  $ms=[IO.MemoryStream]::new(); $bmp.Save($ms,[Drawing.Imaging.ImageFormat]::Png); $data=$ms.ToArray(); $ms.Dispose(); $brush.Dispose(); $pen.Dispose(); $grad.Dispose(); $path.Dispose(); $g.Dispose(); $bmp.Dispose(); return ,$data
}
$sizes=@(16,20,24,32,40,48,64,128,256); $images=@(); foreach($s in $sizes){ $images += [pscustomobject]@{Size=$s;Data=(Render-Logo $s)} }
$iconOut=(Resolve-Path $src).Path+'\app.ico'; $fs=[IO.File]::Create($iconOut); $bw=[IO.BinaryWriter]::new($fs); $bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$images.Count); $offset=6+16*$images.Count
foreach($im in $images){ $wh=if($im.Size -ge 256){[byte]0}else{[byte]$im.Size}; $bw.Write($wh); $bw.Write($wh); $bw.Write([byte]0); $bw.Write([byte]0); $bw.Write([UInt16]1); $bw.Write([UInt16]32); $bw.Write([UInt32]$im.Data.Length); $bw.Write([UInt32]$offset); $offset += $im.Data.Length }
foreach($im in $images){ $bw.Write([byte[]]$im.Data) }; $bw.Dispose(); $fs.Dispose()

# Add normal Windows identity metadata and the asInvoker manifest.
$winres = @'
{
  "RT_GROUP_ICON": { "APP": { "0000": "app.ico" } },
  "RT_MANIFEST": { "#1": { "0409": "app.manifest" } },
  "RT_VERSION": {
    "#1": {
      "0000": {
        "fixed": { "file_version": "3.6.0.0", "product_version": "3.6.0.0" },
        "info": {
          "0409": {
            "FileDescription": "LAN Proxy Share Assistant / 局域网代理共享助手",
            "FileVersion": "3.6.0.0",
            "InternalName": "LANProxyShareAssistant",
            "OriginalFilename": "局域网代理共享助手.exe",
            "ProductName": "局域网代理共享助手",
            "ProductVersion": "3.6.0.0",
            "LegalCopyright": "Copyright 2026"
          }
        }
      }
    }
  }
}
'@
[IO.File]::WriteAllText((Join-Path (Resolve-Path $src) 'winres.json'),$winres,[Text.UTF8Encoding]::new($false))
Push-Location $src
go run github.com/tc-hib/go-winres@latest make --in winres.json --arch amd64 --out rsrc
if(-not (Test-Path '.\rsrc_windows_amd64.syso')){ throw 'Windows resource file was not created' }

# No packer, no UPX, and deliberately no -s/-w symbol stripping.
$env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags='-H=windowsgui' -o '..\局域网代理共享助手.exe' .
Pop-Location
$app=Get-Item '.\lanproxy-native-v360\局域网代理共享助手.exe'
Write-Host "EXE size=$($app.Length) bytes"
if($app.Length -gt 15000000){ throw 'Native EXE unexpectedly exceeds 15 MB' }

# Runtime smoke test.
$exe=(Resolve-Path '.\lanproxy-native-v360\局域网代理共享助手.exe').Path
$p=Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe) -PassThru
$deadline=(Get-Date).AddSeconds(15)
do{ Start-Sleep -Milliseconds 400; $p.Refresh(); if($p.HasExited){throw "App exited early code $($p.ExitCode)"} }until($p.MainWindowHandle -ne 0 -or (Get-Date) -gt $deadline)
if($p.MainWindowHandle -eq 0){ throw 'No main window appeared' }
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class NC { [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r); [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r); public struct RECT { public int Left,Top,Right,Bottom; } }'
$result=[IntPtr]::Zero
if([NC]::SendMessageTimeout($p.MainWindowHandle,0,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$result) -eq [IntPtr]::Zero){ throw 'UI not responding' }
$wr=New-Object NC+RECT; [NC]::GetWindowRect($p.MainWindowHandle,[ref]$wr)|Out-Null; $w=$wr.Right-$wr.Left; $h=$wr.Bottom-$wr.Top
Write-Host "Window size=${w}x${h}"
if($w -ne 960 -or $h -ne 620){ throw "Unexpected window size ${w}x${h}" }
Start-Sleep -Seconds 8
$p.Refresh(); if($p.HasExited){throw 'App exited during background scan'}
$result=[IntPtr]::Zero
if([NC]::SendMessageTimeout($p.MainWindowHandle,0,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$result) -eq [IntPtr]::Zero){ throw 'UI froze during scan' }
Stop-Process $p -Force -ErrorAction SilentlyContinue

# Best-effort Defender check on the Windows build runner.
try {
  $status=Get-MpComputerStatus -ErrorAction Stop
  Write-Host "Defender AntivirusEnabled=$($status.AntivirusEnabled) RealTimeProtectionEnabled=$($status.RealTimeProtectionEnabled)"
  if($status.AntivirusEnabled){
    Start-MpScan -ScanType CustomScan -ScanPath $exe -ErrorAction Stop
    Start-Sleep -Seconds 2
    $hits=Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { ($_.Resources -join ' ') -like "*$exe*" }
    if($hits){ $hits | Format-List *; throw 'Microsoft Defender reported this build on the runner' }
    Write-Host 'Microsoft Defender custom scan returned no detection for this build.'
  }
} catch { Write-Warning $_.Exception.Message }

$hash=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "SHA256=$hash"
Set-Content '.\lanproxy-native-v360\sha256.txt' $hash -Encoding ascii

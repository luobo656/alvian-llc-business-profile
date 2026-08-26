$ErrorActionPreference = 'Stop'
$root = Resolve-Path "$PSScriptRoot\..\.."
$src = Join-Path $root 'lanproxy-native-v370-cpp'
Set-Location $src

Add-Type -AssemblyName System.Drawing
function New-RoundPath([float]$x,[float]$y,[float]$w,[float]$h,[float]$r){
  $p=[Drawing.Drawing2D.GraphicsPath]::new(); $d=$r*2
  $p.AddArc($x,$y,$d,$d,180,90); $p.AddArc($x+$w-$d,$y,$d,$d,270,90)
  $p.AddArc($x+$w-$d,$y+$h-$d,$d,$d,0,90); $p.AddArc($x,$y+$h-$d,$d,$d,90,90); $p.CloseFigure(); return $p
}
function Render-Logo([int]$s){
  $bmp=[Drawing.Bitmap]::new($s,$s,[Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $g=[Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias; $g.PixelOffsetMode=[Drawing.Drawing2D.PixelOffsetMode]::HighQuality; $g.Clear([Drawing.Color]::Transparent)
  $pad=[float]($s*0.045); $rect=[Drawing.RectangleF]::new($pad,$pad,$s-2*$pad,$s-2*$pad); $path=New-RoundPath $rect.X $rect.Y $rect.Width $rect.Height ([float]($s*0.21))
  $bg=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(255,37,99,235)); $g.FillPath($bg,$path)
  $white=[Drawing.Color]::White; $pen=[Drawing.Pen]::new($white,[Math]::Max(1.4,$s*0.052)); $pen.StartCap=[Drawing.Drawing2D.LineCap]::Round; $pen.EndCap=[Drawing.Drawing2D.LineCap]::Round
  $x1=[float]($s*.33);$y1=[float]($s*.50);$x2=[float]($s*.68);$y2=[float]($s*.30);$x3=[float]($s*.68);$y3=[float]($s*.70)
  $g.DrawLine($pen,$x1,$y1,$x2,$y2);$g.DrawLine($pen,$x1,$y1,$x3,$y3)
  $wb=[Drawing.SolidBrush]::new($white);$r=[float]([Math]::Max(1.8,$s*.068));foreach($pt in @(@($x1,$y1),@($x2,$y2),@($x3,$y3))){$g.FillEllipse($wb,[float]$pt[0]-$r,[float]$pt[1]-$r,$r*2,$r*2)}
  $ms=[IO.MemoryStream]::new();$bmp.Save($ms,[Drawing.Imaging.ImageFormat]::Png);$data=$ms.ToArray();$ms.Dispose();$wb.Dispose();$pen.Dispose();$bg.Dispose();$path.Dispose();$g.Dispose();$bmp.Dispose();return ,$data
}
$sizes=@(16,20,24,32,40,48,64,128,256);$images=@();foreach($s in $sizes){$images += [pscustomobject]@{Size=$s;Data=(Render-Logo $s)}}
$ico=Join-Path $src 'app.ico';$fs=[IO.File]::Create($ico);$bw=[IO.BinaryWriter]::new($fs);$bw.Write([UInt16]0);$bw.Write([UInt16]1);$bw.Write([UInt16]$images.Count);$offset=6+16*$images.Count
foreach($im in $images){$wh=if($im.Size -ge 256){[byte]0}else{[byte]$im.Size};$bw.Write($wh);$bw.Write($wh);$bw.Write([byte]0);$bw.Write([byte]0);$bw.Write([UInt16]1);$bw.Write([UInt16]32);$bw.Write([UInt32]$im.Data.Length);$bw.Write([UInt32]$offset);$offset += $im.Data.Length}
foreach($im in $images){$bw.Write([byte[]]$im.Data)};$bw.Dispose();$fs.Dispose()

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'MSVC installation not found' }
$dev = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
$cmd = @"
call "$dev" -arch=x64 -host_arch=x64
cd /d "$src"
rc /nologo /fo resource.res resource.rc
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /O2 /MT /EHsc /DUNICODE /D_UNICODE /permissive- /W3 /FIprelude.h main.cpp resource.res /Fe:"局域网代理共享助手.exe" /link /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /OPT:REF /OPT:ICF
exit /b %errorlevel%
"@
$cmdFile = Join-Path $env:TEMP 'build-lanproxy-v370.cmd'; [IO.File]::WriteAllText($cmdFile,$cmd,[Text.Encoding]::ASCII)
& cmd.exe /d /c $cmdFile
if ($LASTEXITCODE -ne 0) { throw "MSVC build failed with exit code $LASTEXITCODE" }
$exe = Join-Path $src '局域网代理共享助手.exe'; if(-not (Test-Path $exe)){throw 'EXE not generated'}
Write-Host "EXE bytes=$((Get-Item $exe).Length)"

$p=Start-Process -FilePath $exe -WorkingDirectory $src -PassThru
$deadline=(Get-Date).AddSeconds(15);do{Start-Sleep -Milliseconds 300;$p.Refresh();if($p.HasExited){throw "App exited early: $($p.ExitCode)"}}until($p.MainWindowHandle -ne 0 -or (Get-Date)-gt$deadline)
if($p.MainWindowHandle -eq 0){throw 'No main window'}
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class V37Native { [DllImport("user32.dll",SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,IntPtr w,IntPtr l,uint f,uint t,out IntPtr r); [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECT r); public struct RECT{public int Left,Top,Right,Bottom;} }'
$out=[IntPtr]::Zero;if([V37Native]::SendMessageTimeout($p.MainWindowHandle,0,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$out)-eq[IntPtr]::Zero){throw 'UI not responding'}
$wr=New-Object V37Native+RECT;[V37Native]::GetWindowRect($p.MainWindowHandle,[ref]$wr)|Out-Null;Write-Host "Window=$($wr.Right-$wr.Left)x$($wr.Bottom-$wr.Top)"
Start-Sleep -Seconds 7;$p.Refresh();if($p.HasExited){throw 'App exited during scan'};$out=[IntPtr]::Zero;if([V37Native]::SendMessageTimeout($p.MainWindowHandle,0,[IntPtr]::Zero,[IntPtr]::Zero,2,2000,[ref]$out)-eq[IntPtr]::Zero){throw 'UI froze during scan'}
Stop-Process $p -Force -ErrorAction SilentlyContinue

$sig=Get-AuthenticodeSignature $exe;Write-Host "Authenticode status=$($sig.Status)"
$mp=(Get-Command "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" -ErrorAction SilentlyContinue).Source
if(-not $mp){$mp=Get-ChildItem 'C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe' -ErrorAction SilentlyContinue|Sort-Object FullName -Descending|Select-Object -First 1 -ExpandProperty FullName}
if($mp){& $mp -Scan -ScanType 3 -File $exe; $scanExit=$LASTEXITCODE; Write-Host "Defender scan exit=$scanExit"; if($scanExit -notin 0,2){throw "Defender scan returned $scanExit"}}
$hash=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant();Set-Content (Join-Path $src 'sha256.txt') $hash -Encoding ascii;Write-Host "SHA256=$hash"

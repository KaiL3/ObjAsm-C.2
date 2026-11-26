param([string]$Exe, [string]$Mode = "plain", [int]$Port = 25773)
$ErrorActionPreference = "Stop"
$dir = Split-Path $Exe
$p = Start-Process -FilePath $Exe -WorkingDirectory $dir -PassThru
Start-Sleep -Seconds 2

function Open-Conn {
  $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
  $s = $c.GetStream()
  if ($Mode -eq "tls") {
    $cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($a, $b, $d, $e) $true }
    $s = New-Object System.Net.Security.SslStream($s, $false, $cb)
    $s.AuthenticateAsClient("localhost")
  }
  $b = [Text.Encoding]::ASCII.GetBytes("partial message without delimiter")
  $s.Write($b, 0, $b.Length)
  return $c
}

# 20 open connections with unconsumed data
$open = @(); for ($i = 0; $i -lt 20; $i++) { $open += (Open-Conn) }

# Background connector: accepts are in flight while the server shuts down
$ps = [PowerShell]::Create()
[void]$ps.AddScript({
  param($port)
  $n = 0; $end = (Get-Date).AddSeconds(10)
  while ((Get-Date) -lt $end) {
    try { $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $port); $n++; $c.Close() } catch { }
  }
  $n
}).AddArgument($Port)
$h = $ps.BeginInvoke()

Start-Sleep -Seconds 1
$t0 = Get-Date
[void]$p.CloseMainWindow()
$exited = $p.WaitForExit(20000)
$secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
if ($exited) { "Server exited after $secs s, exit code $($p.ExitCode)" }
else { "Server did NOT exit within 20 s (hang)"; Stop-Process -Id $p.Id -Force }
$connects = $ps.EndInvoke($h); $ps.Dispose()
"Background connects: $connects"
foreach ($c in $open) { try { $c.Close() } catch { } }

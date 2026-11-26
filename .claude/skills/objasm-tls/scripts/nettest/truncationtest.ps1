# TLS truncation (review finding O15): a FIN without close_notify must be reported as TLS_TRUNCATED.
# Starts the TLS Test server, runs the cases below and checks the server's OnDisconnected /
# OnHandshakeFailed results in its debug log. The server must be built with DEBUG(LOG) in the
# SysSetup line of NetComTLSServer.asm (the log is written to NETCOMTLSSERVER.dbg in the server
# folder when the server exits). Restore DEBUG(WND) and rebuild afterwards.
param(
  [int]$Port = 25774,
  [switch]$KeepLog                                          # keep NETCOMTLSSERVER.dbg for inspection
)
$ErrorActionPreference = "Stop"
$here = Split-Path $MyInvocation.MyCommand.Path
$dir = Join-Path (Resolve-Path "$here\..\..\..\..\..").Path "Projects\X\NetCom\TLS Test\TLS Test Server"
$TRUNC = "069F6BE7h"                                        # TLS_TRUNCATED = 111111143 (TLS_Context.inc)
$OK = "00000000h"

$cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($a, $b, $d, $e) $true }
function Open-Tls {
  $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
  $c.ReceiveTimeout = 5000
  $ns = $c.GetStream()
  $ssl = New-Object System.Net.Security.SslStream($ns, $true, $cb)
  $ssl.AuthenticateAsClient("localhost")
  $m = [Text.Encoding]::ASCII.GetBytes("Hello`0"); $ssl.Write($m, 0, $m.Length)
  $buf = New-Object byte[] 64; [void]$ssl.Read($buf, 0, 64)  # echo: the session carries data
  return @{ C = $c; Ns = $ns; Ssl = $ssl }
}
function Send-Fin($c, $ns) {
  # FIN only (no close_notify), then read until the server's FIN / RST
  $c.Client.Shutdown([System.Net.Sockets.SocketShutdown]::Send)
  $buf = New-Object byte[] 256; $sum = 0
  try {
    while (($n = $ns.Read($buf, 0, 256)) -gt 0) { $sum += $n }
    $r = "server FIN after $sum bytes"
  } catch { $r = "server reset after $sum bytes" }
  $c.Close(); Start-Sleep -Milliseconds 300
  return $r
}

Get-ChildItem $dir -Filter *.dbg | Remove-Item
$p = Start-Process -FilePath "$dir\NetComTLSServer.exe" -WorkingDirectory $dir -PassThru
Start-Sleep -Seconds 2
$cases = @()
try {
  # 1) Clean close: close_notify first (SslStream.ShutdownAsync, .NET Framework 4.7+), then FIN
  if ([System.Net.Security.SslStream].GetMethod("ShutdownAsync")) {
    $t = Open-Tls; $t.Ssl.ShutdownAsync().Wait()
    $cases += @{ Name = "close_notify + FIN"; Expect = @("D:$OK"); Note = (Send-Fin $t.C $t.Ns) }
  } else { "1) skipped: SslStream.ShutdownAsync not available" }

  # 2) FIN after application data, no close_notify
  $t = Open-Tls
  $cases += @{ Name = "data, FIN without close_notify"; Expect = @("D:$TRUNC"); Note = (Send-Fin $t.C $t.Ns) }

  # 3) FIN in the middle of a TLS record (header announces 64 bytes, 10 sent)
  $t = Open-Tls
  $part = [byte[]](0x17, 0x03, 0x03, 0x00, 0x40) + [byte[]](1..10)
  $t.Ns.Write($part, 0, $part.Length)
  $cases += @{ Name = "FIN inside a record"; Expect = @("D:$TRUNC"); Note = (Send-Fin $t.C $t.Ns) }

  # 4) FIN before any handshake data (TCP connect + close)
  $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port); $c.ReceiveTimeout = 5000; $ns = $c.GetStream()
  $cases += @{ Name = "FIN before the ClientHello"; Expect = @("H:$TRUNC", "D:$TRUNC"); Note = (Send-Fin $c $ns) }

  # 5) FIN inside the ClientHello (record header announces 512 bytes, 20 sent)
  $c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port); $c.ReceiveTimeout = 5000; $ns = $c.GetStream()
  $part = [byte[]](0x16, 0x03, 0x01, 0x02, 0x00) + [byte[]](1..20)
  $ns.Write($part, 0, $part.Length)
  $cases += @{ Name = "FIN inside the ClientHello"; Expect = @("H:$TRUNC", "D:$TRUNC"); Note = (Send-Fin $c $ns) }

  # 6) Server still serves new connections
  $t = Open-Tls
  $cases += @{ Name = "liveness (echo), FIN without close_notify"; Expect = @("D:$TRUNC"); Note = (Send-Fin $t.C $t.Ns) }
} finally {
  [void]$p.CloseMainWindow()
  if (-not $p.WaitForExit(15000)) { "server did not exit (HANG)"; Stop-Process -Id $p.Id -Force }
  else { "server exited, code $($p.ExitCode)" }
}

$log = Get-ChildItem $dir -Filter *.dbg | Select-Object -First 1
if (-not $log) { "No debug log found: build the server with DEBUG(LOG)."; exit 2 }
# Events up to the shutdown (the pending acceptors report OnDisconnected 0 when the listener closes)
$events = @()
foreach ($line in Get-Content $log.FullName) {
  if ($line -match "ListenerCollection.DestroyItem|NetComEngine.Done") { break }
  if ($line -match "^dResult = ([0-9A-F]+h), NetComTLSServerProtocol.OnDisconnected") { $events += "D:" + $Matches[1] }
  elseif ($line -match "^dError = ([0-9A-F]+h), NetComTLSServerProtocol.OnHandshakeFailed") { $events += "H:" + $Matches[1] }
}
$fail = 0; $i = 0
foreach ($case in $cases) {
  $got = @($events[$i..($i + $case.Expect.Count - 1)]); $i += $case.Expect.Count
  $ok = (($got -join ",") -eq ($case.Expect -join ","))
  if (-not $ok) { $fail++ }
  "{0,-4} {1,-44} expected {2,-24} got {3,-24} ({4})" -f $(if ($ok) { "PASS" } else { "FAIL" }), $case.Name, ($case.Expect -join ","), ($got -join ","), $case.Note
}
if ($i -lt $events.Count) { "unexpected further events: " + ($events[$i..($events.Count - 1)] -join ","); $fail++ }
"D = OnDisconnected dResult, H = OnHandshakeFailed dError, $TRUNC = TLS_TRUNCATED"
if (-not $KeepLog) { Remove-Item $log.FullName }
if ($fail) { "$fail case(s) failed"; exit 1 } else { "all cases passed" }

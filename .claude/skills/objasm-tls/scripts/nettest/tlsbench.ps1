# TLS Test server alone: echo load test (nettest.ps1 -Mode tls), wall time and server CPU
$here = Split-Path $MyInvocation.MyCommand.Path
$r = Join-Path (Resolve-Path "$here\..\..\..\..\..").Path "Projects\X\NetCom"   # repository root
$p = Start-Process -FilePath "$r\TLS Test\TLS Test Server\NetComTLSServer.exe" -WorkingDirectory "$r\TLS Test\TLS Test Server" -PassThru
Start-Sleep -Seconds 2
$t0 = Get-Date
try { $out = & "$here\nettest.ps1" -Mode tls -Port 25774 } catch { $out = "TEST ERROR: " + $_.Exception.Message }
$secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
$p.Refresh()
$out | Where-Object { $_ -match "A_echo|D |ERROR" }
"TLS server: test took $secs s, CPU {0:N1} s (user {1:N1} s, kernel {2:N1} s), handles {3}" -f $p.TotalProcessorTime.TotalSeconds, $p.UserProcessorTime.TotalSeconds, $p.PrivilegedProcessorTime.TotalSeconds, $p.HandleCount
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force }


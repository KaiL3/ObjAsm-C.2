param([int]$Port = 25774)
$ErrorActionPreference = "Stop"
$c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
$ns = $c.GetStream()
$cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($a, $b, $d, $e) $true }
$ssl = New-Object System.Net.Security.SslStream($ns, $true, $cb)
$ssl.AuthenticateAsClient("localhost")
$hello = [Text.Encoding]::ASCII.GetBytes("Hello`0")
$ssl.Write($hello, 0, $hello.Length)
$buf = New-Object byte[] 64
$c.ReceiveTimeout = 5000
$n = $ssl.Read($buf, 0, 64)
"Echo before garbage: " + [Text.Encoding]::ASCII.GetString($buf, 0, $n - 1)
# A syntactically valid TLS record header (application data, TLS 1.2) with garbage content
$garbage = New-Object byte[] 69
$garbage[0] = 0x17; $garbage[1] = 0x03; $garbage[2] = 0x03; $garbage[3] = 0x00; $garbage[4] = 64
for ($i = 5; $i -lt 69; $i++) { $garbage[$i] = [byte](($i * 7) % 256) }
$t0 = Get-Date
$ns.Write($garbage, 0, $garbage.Length)
$c.ReceiveTimeout = 70000
try { $r = $ns.Read($buf, 0, 64); $how = "read returned $r" } catch { $how = "exception: " + $_.Exception.InnerException.Message }
"Server closed after " + [math]::Round(((Get-Date) - $t0).TotalSeconds, 2) + " s ($how)"
$c.Close()


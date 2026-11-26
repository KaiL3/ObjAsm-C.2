param([string]$Mode = "plain", [int]$Port = 25773)
$ErrorActionPreference = "Stop"
$rnd = New-Object System.Random 12345

function New-Batch([int]$count) {
  # Messages of random length (1..3000 non-zero bytes), each terminated by a ZTC
  $ms = New-Object System.IO.MemoryStream
  for ($i = 0; $i -lt $count; $i++) {
    $len = $rnd.Next(1, 3000)
    $buf = New-Object byte[] ($len + 1)
    for ($j = 0; $j -lt $len; $j++) { $buf[$j] = [byte](65 + ($j % 26)) }
    $buf[$len] = 0
    $ms.Write($buf, 0, $buf.Length)
  }
  return ,$ms.ToArray()
}

function Open-Stream($client) {
  $ns = $client.GetStream()
  if ($Mode -eq "tls") {
    $cb = [System.Net.Security.RemoteCertificateValidationCallback]{ param($s, $c, $ch, $e) $true }
    $ssl = New-Object System.Net.Security.SslStream($ns, $false, $cb)
    $ssl.AuthenticateAsClient("localhost")
    return $ssl
  }
  return $ns
}

$result = [ordered]@{}

# --- A: one connection, many pipelined messages in large writes ---
$c = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
$s = Open-Stream $c
$total = 0; $msgs = 0
for ($k = 0; $k -lt 40; $k++) {
  $b = New-Batch 250
  $s.Write($b, 0, $b.Length); $total += $b.Length; $msgs += 250
}
$s.Flush()
if ($Mode -eq "tls") {
  # Echo server: read everything back
  $c.ReceiveTimeout = 15000
  $buf = New-Object byte[] 65536; $got = 0
  while ($got -lt $total) { $n = $s.Read($buf, 0, $buf.Length); if ($n -le 0) { break }; $got += $n }
  $result["A_echo"] = "$got/$total bytes"
}
$c.Close()
$result["A_sent"] = "$msgs messages, $total bytes"

# --- B: 8 connections interleaved ---
$cl = @(); $st = @()
for ($i = 0; $i -lt 8; $i++) { $x = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port); $cl += $x; $st += (Open-Stream $x) }
for ($k = 0; $k -lt 10; $k++) { for ($i = 0; $i -lt 8; $i++) { $b = New-Batch 50; $st[$i].Write($b, 0, $b.Length) } }
if ($Mode -eq "tls") { Start-Sleep -Milliseconds 500 }
foreach ($x in $cl) { $x.Close() }
$result["B"] = "8 connections x 500 messages"

# --- C: 200 connections aborted with RST in the middle of a message ---
$aborted = 0
for ($i = 0; $i -lt 200; $i++) {
  $x = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
  $y = Open-Stream $x
  $b = New-Batch 20
  $y.Write($b, 0, $b.Length - 7)          # cut the last message
  $x.Client.LingerState = New-Object System.Net.Sockets.LingerOption($true, 0)
  $x.Client.Close(); $aborted++
}
$result["C"] = "$aborted connections reset"

# --- D: liveness ---
Start-Sleep -Milliseconds 1500
$x = New-Object System.Net.Sockets.TcpClient("127.0.0.1", $Port)
$y = Open-Stream $x
$hello = [Text.Encoding]::ASCII.GetBytes("Hello`0")
$y.Write($hello, 0, $hello.Length)
if ($Mode -eq "tls") {
  $x.ReceiveTimeout = 5000
  $buf = New-Object byte[] 64; $n = $y.Read($buf, 0, 64)
  $result["D"] = "echo: " + [Text.Encoding]::ASCII.GetString($buf, 0, $n - 1)
} else { $result["D"] = "connected and sent" }
$x.Close()
$result.GetEnumerator() | ForEach-Object { "{0,-8} {1}" -f $_.Key, $_.Value }

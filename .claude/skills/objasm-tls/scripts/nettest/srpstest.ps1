param([int]$Clients = 4, [int]$MBytes = 50, [int]$StallSeconds = 10, [int]$MaxSeconds = 240, [switch]$CloseWhileBusy, [switch]$PromptOpen, [int]$ReadChunk = 65536, [int]$ReadDelayMs = 0, [int]$IdleTimeout = 0)
$ErrorActionPreference = "Stop"
$here = Split-Path $MyInvocation.MyCommand.Path
Add-Type -TypeDefinition (Get-Content "$here\SrpsProbe.cs" -Raw) -Language CSharp
$r = Join-Path (Resolve-Path "$here\..\..\..\..\..").Path "Projects\X\NetCom"   # repository root

$backend = Start-Process -FilePath "$r\TLS Test\TLS Test Server\NetComTLSServer.exe" -WorkingDirectory "$r\TLS Test\TLS Test Server" -PassThru
$srps = Start-Process -FilePath "$r\Small Reverse Proxy Server\SRPS.exe" -WorkingDirectory "$r\Small Reverse Proxy Server" -PassThru
$list = @()
try {
  $h = [IntPtr]::Zero
  for ($i = 0; $i -lt 50 -and $h -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 100; $srps.Refresh(); $h = $srps.MainWindowHandle }
  if ($h -eq [IntPtr]::Zero) { throw "SRPS dialog not found" }
  $WM_SETTEXT = 0x000C; $WM_COMMAND = 0x0111
  [void][Win]::SendMessage([Win]::GetDlgItem($h, 1208), $WM_SETTEXT, [IntPtr]::Zero, "127.0.0.1")
  [void][Win]::SendMessage([Win]::GetDlgItem($h, 1210), $WM_SETTEXT, [IntPtr]::Zero, "25774")
  [void][Win]::SendMessage([Win]::GetDlgItem($h, 1104), $WM_SETTEXT, [IntPtr]::Zero, "25772")
  if ($IdleTimeout -gt 0) { [void][Win]::SendMessage([Win]::GetDlgItem($h, 1302), $WM_SETTEXT, [IntPtr]::Zero, "$IdleTimeout") }
  [void][Win]::PostMessage($h, $WM_COMMAND, [IntPtr]1001, [Win]::GetDlgItem($h, 1001))
  Start-Sleep -Seconds 2

  if ($IdleTimeout -gt 0) {
    $maxMs = ($IdleTimeout + 10) * 1000
    $t = [Idle]::SecondsUntilClosed("127.0.0.1", 25772, $maxMs)
    "Idle TLS connection through SRPS (inactivity timeout $IdleTimeout s): " + $(if ($t -lt ($maxMs / 1000) - 0.5) { "closed by SRPS after {0:N2} s" -f $t } else { "NOT closed within {0:N0} s" -f $t })
    return
  }

  $total = [long]$MBytes * 1MB
  for ($i = 0; $i -lt $Clients; $i++) { $c = New-Object EchoClient("127.0.0.1", 25772, $total); $c.ReadChunk = $ReadChunk; $c.ReadDelayMs = $ReadDelayMs; $c.Start(); $list += $c }
  "Started $Clients bidirectional TLS clients through SRPS, $MBytes MB each" + $(if ($ReadDelayMs) { ", slow readers ($ReadChunk B per $ReadDelayMs ms)" } else { "" })

  if ($CloseWhileBusy) {
    Start-Sleep -Seconds 3
    [void][Win]::PostMessage($h, $WM_COMMAND, [IntPtr]1002, [Win]::GetDlgItem($h, 1002))   # Stop (no exit prompt)
    Start-Sleep -Milliseconds 300
    $t0 = Get-Date; [void]$srps.CloseMainWindow(); $ok = $srps.WaitForExit(20000)
    "SRPS closed while busy: exited=$ok after " + [math]::Round(((Get-Date) - $t0).TotalSeconds, 1) + " s" + $(if ($ok) { ", exit code $($srps.ExitCode)" } else { " (HANG)" })
    if (-not $ok) {
      $srps.Refresh()
      "SRPS CPU time: {0:N1} s" -f $srps.TotalProcessorTime.TotalSeconds
      $srps.Threads | ForEach-Object { "  tid {0,6}  {1,-8} {2,-14} cpu {3:N2} s" -f $_.Id, $_.ThreadState, $(if ($_.ThreadState -eq 'Wait') { $_.WaitReason } else { '' }), $_.TotalProcessorTime.TotalSeconds }
      [Wct]::Analyze(@($srps.Threads | ForEach-Object { $_.Id }))
      Start-Sleep -Seconds 3; $srps.Refresh()
      "SRPS CPU time 3 s later: {0:N1} s" -f $srps.TotalProcessorTime.TotalSeconds
    }
    return
  }

  if ($PromptOpen) { Start-Sleep -Seconds 3; [void]$srps.CloseMainWindow(); Start-Sleep -Milliseconds 300; "WM_CLOSE sent: exit prompt is open while the clients stream" }
  $t0 = Get-Date; $stalled = -1; $maxJobs = 0; $maxConn = 0
  $last = @{}; $lastT = @{}; for ($i = 0; $i -lt $Clients; $i++) { $last[$i] = -1; $lastT[$i] = $t0 }
  while ($true) {
    Start-Sleep -Milliseconds 100                         # 0.1 s time resolution
    $srps.Refresh()
    if ($srps.MainWindowTitle -match '(\d+)/(\d+)\s*$') { $maxConn = [math]::Max($maxConn, [int]$matches[1]); $maxJobs = [math]::Max($maxJobs, [int]$matches[2]) }
    $open = 0; $now = Get-Date
    for ($i = 0; $i -lt $Clients; $i++) {
      $c = $list[$i]
      if ($c.ReadDone) { continue }
      $open++
      if ($c.Received -ne $last[$i]) { $last[$i] = $c.Received; $lastT[$i] = $now }
      elseif (($now - $lastT[$i]).TotalSeconds -ge $StallSeconds) { $stalled = $i }
    }
    if ($open -eq 0 -or $stalled -ge 0) { break }
    if (((Get-Date) - $t0).TotalSeconds -gt $MaxSeconds) { "TIMEOUT after $MaxSeconds s"; break }
  }
  $secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
  for ($i = 0; $i -lt $Clients; $i++) { $c = $list[$i]; "client {0}: sent {1:N1} MB, echoed {2:N1} MB {3}" -f ($i + 1), ($c.Sent / 1MB), ($c.Received / 1MB), $c.Error }
  $srps.Refresh()
  "SRPS CPU time: {0:N1} s (user {1:N1} s, kernel {2:N1} s); max connections {3}, max IOJobs in use {4}" -f $srps.TotalProcessorTime.TotalSeconds, $srps.UserProcessorTime.TotalSeconds, $srps.PrivilegedProcessorTime.TotalSeconds, $maxConn, $maxJobs
  if ($stalled -ge 0) {
    "STALL: client $($stalled + 1) without progress for $StallSeconds s (after $secs s)"
    [Wct]::Analyze(@($srps.Threads | ForEach-Object { $_.Id }))
    $cpu0 = @{}; $srps.Threads | ForEach-Object { $cpu0[$_.Id] = $_.TotalProcessorTime.TotalSeconds }
    Start-Sleep -Seconds 2; $srps.Refresh()
    "Threads (CPU seconds used in the last 2 s):"
    $srps.Threads | ForEach-Object { "  tid {0,6}  {1,-8} {2,-14} +{3:N2} s" -f $_.Id, $_.ThreadState, $(if ($_.ThreadState -eq 'Wait') { $_.WaitReason } else { '' }), ($_.TotalProcessorTime.TotalSeconds - $cpu0[$_.Id]) }
    "Wait chains again:"
    [Wct]::Analyze(@($srps.Threads | ForEach-Object { $_.Id }))
  } elseif ($open -eq 0) {
    $mb = [math]::Round($Clients * $MBytes * 2 / $secs, 1)
    "All echoes complete after $secs s ($mb MB/s through the proxy, both directions)"
    $c0 = $srps.TotalProcessorTime.TotalSeconds; Start-Sleep -Seconds 3; $srps.Refresh()
    "SRPS CPU while idle: {0:N2} s in 3 s" -f ($srps.TotalProcessorTime.TotalSeconds - $c0)
  }
} finally {
  foreach ($c in $list) { $c.Close() }
  foreach ($p in @($srps, $backend)) { $p.Refresh(); if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } }
}



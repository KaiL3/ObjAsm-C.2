# Stress Test client: connection lifetime vs. application threads (review finding O17).
# The client keeps a connection pointer in its send dialog and sends from its own thread. The server
# is killed while the client streams, so the engine destroys the connection on its own; then the
# dialog's Disconnect is used. Then a second, regular connect/disconnect cycle, then a clean exit.
$ErrorActionPreference = "Stop"
$here = Split-Path $MyInvocation.MyCommand.Path
$r = Join-Path (Resolve-Path "$here\..\..\..\..\..").Path "Projects\X\NetCom\Stress Test"
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class Wnd {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  public static string[] Titles(int pid) {
    var r = new System.Collections.Generic.List<string>();
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p);
      if (p == pid && IsWindowVisible(h)) { var c = new StringBuilder(64); GetClassName(h, c, 64); var t = new StringBuilder(128); GetWindowText(h, t, 128); r.Add(c + " '" + t + "'"); }
      return true; }, IntPtr.Zero);
    return r.ToArray();
  }
  public static IntPtr FindDialog(int pid, IntPtr exclude) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || h == exclude || !IsWindowVisible(h)) return true;
      StringBuilder sb = new StringBuilder(64); GetClassName(h, sb, 64);
      if (sb.ToString() == "#32770") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@
$WM_COMMAND = 0x0111; $WM_SETTEXT = 0x000C
function Start-Server { Start-Process -FilePath "$r\Stress Test Server\NetComStressServer.exe" -WorkingDirectory "$r\Stress Test Server" -PassThru }
function Click($h, $id) { [void][Wnd]::PostMessage($h, $WM_COMMAND, [IntPtr]$id, [Wnd]::GetDlgItem($h, $id)) }
function Alive($p, $what) { $p.Refresh(); "{0,-48} client alive: {1}" -f $what, (-not $p.HasExited) }

$srv = Start-Server
$cli = Start-Process -FilePath "$r\Stress Test Client\NetComStressClient.exe" -WorkingDirectory "$r\Stress Test Client" -PassThru
try {
  Start-Sleep -Seconds 2
  $cli.Refresh(); $main = $cli.MainWindowHandle
  [void][Wnd]::PostMessage($main, $WM_COMMAND, [IntPtr]1000, [IntPtr]::Zero)   # IDM_SEND: open the send dialog
  $dlg = [IntPtr]::Zero
  for ($i = 0; $i -lt 30 -and $dlg -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 100; $dlg = [Wnd]::FindDialog($cli.Id, $main) }
  if ($dlg -eq [IntPtr]::Zero) { throw "send dialog not found" }
  [void][Wnd]::SendMessage([Wnd]::GetDlgItem($dlg, 1005), $WM_SETTEXT, [IntPtr]::Zero, "127.0.0.1")
  [void][Wnd]::SendMessage([Wnd]::GetDlgItem($dlg, 1007), $WM_SETTEXT, [IntPtr]::Zero, "25773")

  # 1) Streaming, server killed, then Disconnect on the connection the engine has destroyed
  Click $dlg 1; Start-Sleep -Seconds 3
  $est = @(Get-NetTCPConnection -RemotePort 25773 -State Established -ErrorAction SilentlyContinue).Count
  Alive $cli "connected and streaming ($est established)"
  Stop-Process -Id $srv.Id -Force
  Start-Sleep -Seconds 3
  Alive $cli "server killed, engine destroyed the connection"
  Click $dlg 1002; Start-Sleep -Seconds 2
  Alive $cli "Disconnect on the destroyed connection"

  # 2) Regular cycle: connect, stream, Disconnect while the connection exists
  $srv = Start-Server; Start-Sleep -Seconds 2
  Click $dlg 1; Start-Sleep -Seconds 3
  $est = @(Get-NetTCPConnection -RemotePort 25773 -State Established -ErrorAction SilentlyContinue).Count
  Alive $cli "reconnected and streaming ($est established)"
  Click $dlg 1002; Start-Sleep -Seconds 2
  Alive $cli "Disconnect on the live connection"

  # 3) Clean exit
  Click $dlg 2; Start-Sleep -Milliseconds 500                     # IDCANCEL closes the dialog
  [void][Wnd]::PostMessage($main, $WM_COMMAND, [IntPtr]1001, [IntPtr]::Zero)   # IDM_EXIT
  Start-Sleep -Milliseconds 500
  $ask = [Wnd]::FindDialog($cli.Id, $main)                        # "Application exit" prompt
  if ($ask -ne [IntPtr]::Zero) { [void][Wnd]::PostMessage($ask, $WM_COMMAND, [IntPtr]6, [IntPtr]::Zero) }   # IDYES
  $ok = $cli.WaitForExit(15000)
  "client exited: $ok" + $(if ($ok) { ", exit code $($cli.ExitCode)" } else { " (HANG)" })
  if (-not $ok) {
    "visible windows of the client: " + ([Wnd]::Titles($cli.Id) -join " | ")
    Add-Type -TypeDefinition (Get-Content "$here\SrpsProbe.cs" -Raw) -Language CSharp
    $cli.Refresh()
    $cli.Threads | ForEach-Object { "  tid {0,6}  {1,-8} {2,-14} cpu {3:N2} s" -f $_.Id, $_.ThreadState, $(if ($_.ThreadState -eq 'Wait') { $_.WaitReason } else { '' }), $_.TotalProcessorTime.TotalSeconds }
    [Wct]::Analyze(@($cli.Threads | ForEach-Object { $_.Id }))
  }
} finally {
  foreach ($p in @($cli, $srv)) { $p.Refresh(); if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } }
  Get-Process DebugCenter -ErrorAction SilentlyContinue | ForEach-Object { [void]$_.CloseMainWindow() }
}

# NetCom / TLS / SRPS runtime tests

PowerShell scripts that drive the NetCom sample programs from outside (no GUI interaction needed).
They were written during the NetCom control-flow review (2026-11-26, findings O23-O35 in
`../../references/known-issues.md`).

Run every script in a fresh process, e.g. `powershell -NoProfile -ExecutionPolicy Bypass -File srpstest.ps1`,
so `Add-Type` never meets an older compiled `SrpsProbe.cs` in the same session.

## Before running

- Build the programs first (`Projects/X/NetCom/...`). For load and timing tests use **release builds**:
  comment out `DEBUG(WND)` in the `SysSetup` line of the server's main `.asm`. A debug build starts the
  DebugCenter, which then takes a whole CPU and slows the program down so much that results look like
  a regression. Restore the line afterwards and close a DebugCenter that a test started.
- TLS tests need the server certificate of the TLS Test server (subject "ObjAsm TLS Test"), see
  `Projects/X/NetCom/TLS Test/TLS Test Server/README.md`.
- Ports: Core Test server 25773, TLS Test server 25774, SRPS 25772 (forwarding to 127.0.0.1:25774).
- **Keep the load moderate.** An 8 x 100 MB run through SRPS (before the send backpressure fix, with
  more than 100,000 pending sends) ended in a bluescreen 0x133 DPC_WATCHDOG_VIOLATION in `afd.sys`.
  4 x 50 MB is enough to see every effect.

## Scripts

| Script | Target | What it does |
|---|---|---|
| `nettest.ps1 -Mode plain\|tls -Port n` | running Core Test server (plain) or TLS Test server (tls) | A: 10,000 pipelined ZTC messages (15 MB) on one connection (TLS: echo read back completely); B: 8 interleaved connections; C: 200 connections reset with RST in the middle of a message; D: liveness check |
| `shutdowntest.ps1 -Exe path -Mode plain\|tls -Port n` | starts the server itself | 20 open connections plus a client connecting in a loop, then WM_CLOSE: the server must exit within seconds with exit code 0 |
| `garbagetest.ps1 -Port 25774` | running TLS Test server | TLS handshake + echo, then a garbage TLS record on the raw stream: the server must reset the connection at once (decrypt error path) |
| `tlsbench.ps1` | starts the TLS Test server | `nettest.ps1 -Mode tls` with wall time and server CPU (user/kernel) |
| `srpstest.ps1` | starts TLS Test server + SRPS, configures and starts SRPS through its dialog | bidirectional TLS clients through the proxy, see below |

`srpstest.ps1` parameters:

| Parameter | Meaning |
|---|---|
| `-Clients n -MBytes m` | n TLS clients, each writes m MB and reads the echo at the same time (default 4 x 50) |
| `-StallSeconds s -MaxSeconds t` | a client without progress for s seconds counts as stalled; overall limit t |
| `-ReadChunk b -ReadDelayMs d` | slow readers: read b bytes, then sleep d ms (backpressure test) |
| `-CloseWhileBusy` | press Stop, then close SRPS while the clients stream (shutdown under load) |
| `-PromptOpen` | close SRPS without Stop: the exit prompt stays open while the clients stream |
| `-IdleTimeout s` | set the inactivity timeout in the SRPS dialog, then measure when an idle TLS connection is closed |

Output: per client sent/echoed MB, SRPS CPU (user/kernel), maximum connections and IOJobs in use (read
from the SRPS window title every 0.1 s), throughput, CPU while idle afterwards. On a stall it prints the
thread states and the **Wait Chain Traversal** result (`GetThreadWaitChain`): a deadlock between
critical sections shows up as `CYCLE: Thread(a) -> CritSect -> Thread(b) -> CritSect -> Thread(a)`.

`SrpsProbe.cs` (compiled by `srpstest.ps1`) contains `EchoClient` (bidirectional TLS client with
optional slow reader), `Idle` (idle connection timing), `Win` (dialog control) and `Wct` (wait chain
analysis). It can be reused for other targets.

## Reference results (Windows 10, 8 logical CPUs, 2026-11-26, release builds)

| Test | Result |
|---|---|
| SRPS 4 x 50 MB, 16 KB IOJobs in SRPS and TLS server | 0.75-0.85 s (470-533 MB/s through the proxy), SRPS CPU ~2 s, max ~25-240 IOJobs |
| Slow readers 2 x 10 MB, 16 KB per 20 ms | complete in ~20.4 s, no stall |
| SRPS Stop + close while streaming | exit code 0 after 0.5-0.6 s |
| Core / TLS server shutdown with 20 connections + connect loop | exit code 0 after 0.6 s |
| TLS garbage record | connection reset after 0.02-0.04 s |
| SRPS inactivity timeout 3 s / 5 s | idle connection closed after 3.23 s / 5.14 s |

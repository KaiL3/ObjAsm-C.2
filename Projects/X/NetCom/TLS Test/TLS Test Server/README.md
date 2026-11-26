# NetCom TLS Test Server

A Windows GUI test server for the ObjAsm NetCom engine with TLS (SChannel). It accepts TLS
connections, receives zero-terminated messages, optionally echoes them back and exposes every
TLS and NetCom parameter in a settings dialog. Test actions (pause/resume receive, graceful
disconnect, abort) and live statistics make it a test bench for the NetCom/TLS layer.

Counterpart: [`../TLS Test Client`](../TLS%20Test%20Client/README.md). Any other TLS client
works as well (`openssl s_client`, `curl`, .NET `SslStream`, see [Headless tests](#headless-tests)).

---

## Contents

1. [Quick start](#quick-start)
2. [Files](#files)
3. [User interface](#user-interface)
4. [Settings](#settings)
5. [Message protocol](#message-protocol)
6. [Test scenarios](#test-scenarios)
7. [Headless tests](#headless-tests)
8. [Implementation notes](#implementation-notes)
9. [Limitations](#limitations)

---

## Quick start

### Prerequisites

- ObjAsm C.2 with `OBJASM_PATH` pointing to the checkout you build from. On a machine where
  it points to another checkout, override it per build (see the repository `CLAUDE.md`).
- A server certificate **with private key** in a certificate store, by default
  `CurrentUser\MY` with a subject containing `ObjAsm TLS Test`.
- For DEBUG builds: DebugCenter, which shows the output windows `NetComTLSServer` and
  `TLS Server Protocol`.

### Certificates

The `TLS Test` folder contains two ways to get a certificate:

| Way | Files | Result |
|---|---|---|
| Own test CA (recommended) | `crt_ca.cmd`, `crt_server.cmd`, `crt_client.cmd`, `*_ext.cnf` (needs `openssl`) | CA `ObjAsm Test CA` in `CurrentUser\Root`, server certificate `ObjAsm TLS Test` (SAN `localhost`, `127.0.0.1`, EKU serverAuth) and client certificate `ObjAsm Test Client` (EKU clientAuth) in `CurrentUser\MY` |
| Self-signed | `GenerateCert.ps1` | Self-signed `ObjAsm TLS Test` in `CurrentUser\MY` plus `ObjAsmTLSTest.pfx` |

At startup `InstallTestCertificate` (`../TLS_TestCert.inc`) looks for `ObjAsm TLS Test` in
`CurrentUser\MY` and, if it is missing, imports `..\ObjAsmTLSTest.pfx` (password `test`).

Clients validate the server certificate (the NetCom client fails closed), so the issuing CA
must be trusted on the client machine. With the own test CA this is done by `crt_ca.cmd`.

### Build and run

```bat
cd "Projects\X\NetCom\TLS Test\TLS Test Server"
Make.cmd
NetComTLSServer.exe
```

The target is defined by the `SysSetup` line in `NetComTLSServer.asm` (currently
`WIN64, ANSI_STRING, DEBUG(WND)`). A DEBUG build keeps `Make.log`. A failed build leaves
`NetComTLSServer.err`; fix the first error listed there. Every build increments the build number
in `NetComTLSServer_Shared.inc` and regenerates `NetComTLSServer_Shared.rc`.

The server listens on port **25774** on all interfaces (IPv4, see `INTERNET_PROTOCOL_VERSION`).

---

## Files

| File | Content |
|---|---|
| `NetComTLSServer.asm` | Main file: `SysSetup`, includes, `MakeObjects`, entry point. Defines `TLS_TEST_ROLE equ 1` (server). |
| `NetComTLSServer_Main.inc` | Application object `NetComTLSServer` (SDI window, menus, status display, settings handling). |
| `NetComTLSServer_Protocol.inc` | Protocol object `NetComTLSServerProtocol` (TLS context per connection, message handling, echo, statistics). |
| `NetComTLSServer_Globals.inc` | Title and About text. |
| `NetComTLSServer_Shared.inc` | Version, build number, menu IDs. `NetComTLSServer_Shared.rc` is generated from it during the build. |
| `NetComTLSServer.rc` | Resources: icon, menu, About dialog, settings dialog. |
| `../TLS_TestCommon.inc` | Shared with the client: settings and INI file, TLS config snapshots, certificate provider `TestCertProv`, statistics, message scanning, connection actions, algorithm and store enumeration. |
| `../TLS_TestSettingsDlg.inc`, `.rc` | Shared settings dialog `TestSettingsDlg`. |
| `../TLS_TestCert.inc` | Test certificate installation. |

The shared files are role dependent: `TLS_TEST_ROLE` selects defaults, dialog layout, the
SChannel protocol flags and the ancestor of `TestCertProv`
(`TLS_DefaultServerCertProvider` here, `TLS_DefaultClientCertProvider` in the client).

---

## User interface

### Status display (refreshed every 100 ms)

| Line | Meaning |
|---|---|
| `#Workers`, `#Listeners` | IOCP worker threads, listening sockets |
| `#Connections` | Connection objects in the pool, **including** pending acceptors (3 per listener) |
| `#IOJobs` | IOJobs in use (receive, send, accept) |
| `#In/Out Bytes`, `#In/Out Rate` | Engine throughput counters |
| `#Handshakes ok / failed` | Completed / failed TLS handshakes |
| `#Errors, last, truncated` | Errors reported through `OnError`, last code in decimal and hex; disconnects with `TLS_TRUNCATED` (client closed with a FIN but without close_notify) |
| `#Messages, echo dropped` | Received zero-terminated messages; echoes not queued completely (send backpressure) |
| `#Paused connections` | Connections with `NCC_RCV_PAUSED` |

The most frequent error codes:

| Code | Name | Meaning |
|---|---|---|
| 111111122 | `NCCN_RCV_LIMIT_EXCEEDED` | More unconsumed received data than the receive limit |
| 111111123 | `NCCN_RCV_PAUSE_TIMEOUT` | Receive pause longer than the pause timeout |
| 111111134 | `TLS_CERTIFICATE_INVALID` | Peer certificate rejected by the validator (chain, EKU, name) |
| 111111142 | `TLS_HANDSHAKE_TIMEOUT` | Initial handshake not completed within the handshake timeout |
| 111111143 | `TLS_TRUNCATED` | Peer closed (FIN) without close_notify. In `OnDisconnected` (`truncated` counter); during the handshake also `#Handshakes failed` and `OnError` |
| 0x80090331 | `SEC_E_ALGORITHM_MISMATCH` | No common protocol version / cipher suite |

The NetCom and TLS error codes are generated by `AddErrMsg` (see `NetCom.inc`,
`TLS_Context.inc`). Their values change if entries are inserted there, so check the source when
in doubt.

### Menus

| Menu | Item | Effect |
|---|---|---|
| File | Settings... | Opens the settings dialog (see [Settings](#settings)). |
| File | Exit | Closes the server. |
| Actions | Pause receive (all) | `PauseReceive` on every established connection: no new `WSARecv` is posted. The client is throttled by the TCP zero window. |
| Actions | Resume receive (all) | `ResumeReceive` on every connection. |
| Actions | Disconnect all (graceful) | `Disconnect(SD_SEND)`: close_notify + FIN. Lifts a receive pause. |
| Actions | Abort all (RST) | `QueueDestroy` + `Close(TRUE)`: abortive close. |
| Actions | Reset statistics | Clears the TLS test counters. |

The actions skip pending acceptors, connections that are already closing and connections that
are busy in a worker thread at that moment. The number of affected connections is written to
DebugCenter.

---

## Settings

**File > Settings** edits a working copy. **OK** validates all fields, stores them in
`NetComTLSServer.ini` (next to the executable, section `[Settings]`) and applies them.
**Defaults** resets the dialog to the built-in defaults.

| Dialog field | INI key | Default | Applies |
|---|---|---|---|
| TLS 1.0 / 1.1 / 1.2 / 1.3 | `Protocols` (bits 1/2/4/8) | 12 (TLS 1.2 + 1.3) | to new connections |
| Require client certificate | `MutualAuth` | 0 | to new connections |
| Certificate: Search by | `CertSearch` (1 subject, 2 serial, 3 thumbprint) | 1 | to new connections |
| Certificate: Value | `CertValue` | `ObjAsm TLS Test` | to new connections |
| Certificate: Scope | `CertScope` (0 current user, 1 local machine) | 0 | to new connections |
| Certificate: Store | `CertStore` | `MY` | to new connections |
| Algorithms | `Ciphers` (ALG_ID hex list) | empty | to new connections |
| Listening port | `Port` | 25774 | immediately (listeners are recreated) |
| Inactivity timeout [s] | `InactivityTimeout` | 60 | immediately |
| Handshake timeout [s] | `HandshakeTimeout` | 15 | immediately |
| TLS shutdown timeout [s] | `TLSShutdownTimeout` | 5 | immediately |
| Receive pause timeout [s] | `RcvPauseTimeout` | 60 | immediately |
| Receive limit [KB] | `RcvLimitKB` | 1024 | immediately |
| Echo received messages | `Echo` | 1 | immediately |

Notes:

- **Timeouts**: 0 disables a timeout. The maximum is 429 s, because NetCom stores them as DWORD
  in 100 ns units. The inactivity timeout counts from the last I/O completion, the handshake
  timeout from the start of the connection (it also catches a client that trickles handshake
  bytes). A paused connection has no inactivity timeout, the pause timeout applies instead.
- **Receive limit**: maximum of received bytes the protocol has not consumed yet. Exceeding it
  aborts the connection with `NCCN_RCV_LIMIT_EXCEEDED`. Set it to at least the largest message.
- **Certificate value**: subject search is a substring match (first hit wins). Serial number
  and thumbprint are hex bytes; blanks, `:` and `-` are ignored. The serial number is entered as
  displayed by Windows (big-endian). The certificate must have a private key.
- **Store**: the combo box lists the system stores of the selected scope; a custom name can be
  typed in.
- **Algorithms**: the list shows the ALG_IDs SChannel offers on this host
  (`QueryCredentialsAttributes(SECPKG_ATTR_SUPPORTED_ALGS)`), grouped by class. No selection =
  SChannel default. SChannel restricts only the classes that contain a selected entry; if no
  cipher suite matches, the handshake fails with `SEC_E_ALGORITHM_MISMATCH`.

---

## Message protocol

Application messages are **zero-terminated** (ZTC). `IsDataComplete?` reports the data up to and
including the last ZTC; `ProcessData` counts the messages, shows the first one in DebugCenter
and, with **Echo** enabled, sends the whole block back unchanged.

Data without a terminating zero stays buffered until more data arrives. That is what the receive
limit test uses.

---

## Test scenarios

| # | Scenario | Steps | Expected |
|---|---|---|---|
| 1 | Handshake and echo | Client: connect, send a message. | `#Handshakes ok` +1, `#Messages` +1, the client receives the echo. |
| 2 | Mutual authentication | Server: *Require client certificate*. Client: *Send client certificate if requested* with an existing client certificate. | Handshake ok. Without a client certificate: `#Handshakes failed` +1. |
| 3 | Protocol / algorithms | Restrict TLS versions or algorithms on one side. | Handshake ok with the negotiated parameters (client log) or `SEC_E_ALGORITHM_MISMATCH`. |
| 4 | Handshake timeout | Client: *Raw TCP handshake trickle* + Connect. | Connection is closed after the handshake timeout, `TLS_HANDSHAKE_TIMEOUT`. |
| 5 | Receive limit | Server: limit e.g. 64 KB. Client: *Send without delimiter*, repetitions so that > 64 KB are sent. | Connection aborted, `NCCN_RCV_LIMIT_EXCEEDED`. With limit 0 the connection stays open. |
| 6 | Receive pause | Actions > Pause receive (all), client keeps sending. | `#Paused connections` > 0, the client gets throttled (no data loss). Resume: data is processed. |
| 7 | Pause timeout | As 6, do not resume. | Abort after the pause timeout, `NCCN_RCV_PAUSE_TIMEOUT`. |
| 8 | Inactivity | Connect a client and send nothing after the handshake. | Disconnect after the inactivity timeout. |
| 9 | Graceful / abortive close | Actions > Disconnect all / Abort all. | Client sees close_notify + FIN or RST. |
| 10 | Port change | Settings: new port, OK. | The caption shows the new port, new clients connect there. |
| 11 | Truncation | A client closes the TCP connection without close_notify (see headless tests). | `truncated` +1. Before the handshake has completed also `#Handshakes failed` +1 and `TLS_TRUNCATED` as last error. A client that sends close_notify first does not count. |

---

## Headless tests

The server can be tested without the client GUI from PowerShell with .NET `SslStream`. The
callback accepts every certificate; that is fine for testing the server only.

```powershell
# Handshake + echo
$c   = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 25774)
$ssl = New-Object System.Net.Security.SslStream($c.GetStream(), $false,
         ({ $true } -as [System.Net.Security.RemoteCertificateValidationCallback]))
$ssl.AuthenticateAsClient('ObjAsm TLS Test', $null,
         [System.Security.Authentication.SslProtocols]::Tls12, $false)
$ssl.Write([Text.Encoding]::ASCII.GetBytes("hello`0"))
$buf = New-Object byte[] 256; $n = $ssl.Read($buf, 0, 256)
"$($ssl.CipherAlgorithm) / " + [Text.Encoding]::ASCII.GetString($buf, 0, $n)
$c.Close()
```

```powershell
# Handshake timeout: TLS record header announcing 512 bytes, then 1 byte per second
$c = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 25774); $s = $c.GetStream()
$s.Write([byte[]](0x16,0x03,0x01,0x02,0x00), 0, 5)
$t = [Diagnostics.Stopwatch]::StartNew()
try { while ($true) { Start-Sleep 1; $s.Write([byte[]](0), 0, 1) } }
catch { "closed after {0:N1} s" -f $t.Elapsed.TotalSeconds }
```

Truncation: after the echo above, `$c.Client.Shutdown('Send')` instead of `$c.Close()` sends a FIN
without close_notify (`truncated` +1); `$ssl.ShutdownAsync().Wait()` first sends close_notify (no
count). `.claude/skills/objasm-tls/scripts/nettest/truncationtest.ps1` runs all truncation cases
automatically; it needs a server built with `DEBUG(LOG)` and reads the results from its debug log.

For the receive limit, write a few MB without a zero byte, wait some seconds and then call
`Read`: an aborted connection throws "connection was closed by the remote host".
The data in the socket buffers hides the RST, so a failing `Write` alone is not a reliable
indicator.

To test other settings without the GUI, write the INI file before starting the executable and
delete it afterwards:

```ini
[Settings]
RcvLimitKB=64
Ciphers=660E, 800C, AE06
```

Results recorded on 2026-11-25 (Windows 10): echo ok, trickle closed after 15.1 s,
limit 0 open / 64 KB and 1024 KB aborted, `Ciphers=660E,...` -> AES 128, `Ciphers=6610` -> AES 256.
2026-11-26: truncation test, all 6 cases as expected.

---

## Implementation notes

- **TLS config snapshots.** `NetComTLSServerProtocol.Reconfigure` builds a new
  `TLS_Connection_Config` plus `TestCertProv` from the settings (`TestNewTLSConfig`) and switches
  `pTLSConfig` with one pointer write. `OnConfigureTLS` hands the current snapshot to every new
  connection. Running connections still reference their old snapshot (the context keeps pointers
  to the provider and the cipher array), so old snapshots go into the `Graveyard` collection and
  are destroyed in `Done`, after `NetComEngine.Done`. A shared config is never mutated.
- **Certificate provider.** `TestCertProv` copies store name, subject string or hex blob into its
  own `TT_CERT_SEARCH` buffer, because `TLS_CertProvider` stores only pointers. The SNI name is
  dumped by `TLS_DefaultServerCertProvider.GetServerCert`.
- **Live parameters.** The supervisor template `$ObjTmpl(NetComSupervisor)` is the running
  supervisor instance and the protocol template is the protocol of the listeners, so
  `TestApplyNetCom` changes timeouts and the receive limit at runtime.
- **Threading.** Protocol callbacks run in IOCP worker threads: statistics are updated with
  `lock` instructions, nothing touches the UI. `TestConnectionsAction` runs in the UI thread,
  holds the connection pool lock and uses `TryEnterCriticalSection` per connection, so it never
  blocks while a worker owns a connection.
- **Message scanning.** `TestFindDelimiter` rescans the whole `PlaintextChain` on every receive.
  That is O(n^2) for large unterminated data, bounded by the receive limit.

---

## Limitations

- Timeouts are limited to 429 s.
- The library uses `SCHANNEL_CRED`. Cipher restrictions therefore work on ALG_IDs, not on named
  cipher suites. Windows 10 SChannel does not negotiate TLS 1.3.
- Changing the port recreates the listeners with `StopListening` / `StartListening`. Existing
  connections are not affected.
- The settings dialog, the Actions menu and mutual authentication have been built but not yet
  exercised systematically through the GUI; the server-side behaviour of scenarios 1, 4, 5 and 3
  (ciphers) was verified headless.

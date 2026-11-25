# NetCom TLS Test Client

A Windows GUI test client for the ObjAsm NetCom engine with TLS (SChannel). It opens any number
of parallel TLS connections, sends zero-terminated messages, counts the replies and exposes every
TLS and NetCom parameter in a settings dialog. Test options cover the receive limit, the TLS
handshake timeout (raw trickle), receive pause/resume and abortive close.

Counterpart: [`../TLS Test Server`](../TLS%20Test%20Server/README.md), which echoes the messages.
Any other TLS server works as well, for example `openssl s_server`.

---

## Contents

1. [Quick start](#quick-start)
2. [Files](#files)
3. [User interface](#user-interface)
4. [Settings](#settings)
5. [Test scenarios](#test-scenarios)
6. [Implementation notes](#implementation-notes)
7. [Limitations](#limitations)

---

## Quick start

### Prerequisites

- ObjAsm C.2 with `OBJASM_PATH` pointing to the checkout you build from. On a machine where
  it points to another checkout, override it per build (see the repository `CLAUDE.md`).
- The client **validates the server certificate** (fail closed): the chain must lead to a trusted
  root, the certificate needs EKU serverAuth, and with *Verify server name* the target name must
  match the certificate (CN / SAN).
- For mutual authentication: a client certificate with private key and EKU clientAuth, by default
  `CurrentUser\MY` with a subject containing `ObjAsm Test Client`.
- For DEBUG builds: DebugCenter, which shows the output windows `NETCOMTLSCLIENT` and
  `TLS Client Protocol` (handshake details, negotiated protocol and algorithms, server
  certificate).

### Certificates

Run the scripts in the `TLS Test` folder (they need `openssl`):

| Script | Result |
|---|---|
| `crt_ca.cmd` | Test CA `ObjAsm Test CA`, added to `CurrentUser\Root` (trust for the server certificate) |
| `crt_server.cmd` | Server certificate `ObjAsm TLS Test`, SAN `localhost` and `127.0.0.1`, in `CurrentUser\MY` |
| `crt_client.cmd` | Client certificate `ObjAsm Test Client`, in `CurrentUser\MY` |

A self-signed server certificate from `GenerateCert.ps1` is **not** trusted by the client unless
it is added to a root store.

### Build and run

```bat
cd "Projects\X\NetCom\TLS Test\TLS Test Client"
Make.cmd
NetComTLSClient.exe
```

The target is defined by the `SysSetup` line in `NetComTLSClient.asm` (currently
`WIN64, ANSI_STRING, DEBUG(WND)`). A DEBUG build keeps `Make.log`. A failed build leaves
`NetComTLSClient.err`; fix the first error listed there. Every build increments the build number
in `NetComTLSClient_Shared.inc` and regenerates `NetComTLSClient_Shared.rc`.

### First connection

1. Start the server.
2. Client: **File > Send...**
3. Address `localhost` (or `127.0.0.1`), port `25774`, connections `1`, **Connect**.
4. Enter a text, **Send**. With the server echo enabled, `#Messages` increases on both sides.

---

## Files

| File | Content |
|---|---|
| `NetComTLSClient.asm` | Main file: `SysSetup`, includes, `MakeObjects`, entry point. Defines `TLS_TEST_ROLE equ 2` (client). |
| `NetComTLSClient_Main.inc` | Application object `NetComTLSClient` (SDI window, status display, settings, trickle timer) and the Send dialog `SendDlg`. |
| `NetComTLSClient_Protocol.inc` | Protocol object `NetComTLSClientProtocol` (TLS context per connection, raw mode, message counting, handshake details, statistics). |
| `NetComTLSClient_Globals.inc` | Title and About text. |
| `NetComTLSClient_Shared.inc` | Version, build number, menu and control IDs. `NetComTLSClient_Shared.rc` is generated from it during the build. |
| `NetComTLSClient.rc`, `Res/SendDlg.rc` | Resources: icon, menu, About, Send and settings dialog. |
| `../TLS_TestCommon.inc` | Shared with the server: settings and INI file, TLS config snapshots, certificate provider `TestCertProv`, statistics, message scanning, connection actions, algorithm and store enumeration. |
| `../TLS_TestSettingsDlg.inc`, `.rc` | Shared settings dialog `TestSettingsDlg`. |
| `../TLS_TestCert.inc` | Test certificate installation (needed by the server; the client calls it too). |

`TLS_TEST_ROLE` selects the client variant of the shared code: client protocol flags, dialog
layout, defaults and `TLS_DefaultClientCertProvider` as ancestor of `TestCertProv`.

---

## User interface

### Main window

The status display is refreshed every 500 ms.

| Line | Meaning |
|---|---|
| `#Workers`, `#Connections`, `#IOJobs` | IOCP worker threads, connection objects, IOJobs in use |
| `#In/Out Bytes`, `#In/Out Rate` | Engine throughput counters |
| `#Handshakes ok / failed` | Completed / failed TLS handshakes |
| `#Errors, last` | Errors reported through `OnError`, last code in decimal and hex |
| `#Messages` | Zero-terminated messages received (for example the server echo) |
| `#Paused connections` | Connections with a paused receive |

Error codes are listed in the server README. On the client side `111111134`
(`TLS_CERTIFICATE_INVALID`) is the typical result of an untrusted CA or a name mismatch.

| Menu item | Effect |
|---|---|
| File > Send... | Opens the Send dialog. |
| File > Settings... | Opens the settings dialog. Timeouts and the receive limit apply immediately, TLS settings with the next **Connect**. |
| File > Reset statistics | Clears the TLS test counters. |
| File > Exit | Closes the client. |

### Send dialog

| Control | Effect |
|---|---|
| Address | Server name or IP. The list offers local adapter addresses and known neighbours. Unless a target name is set in the settings, the address is also the TLS target name (SNI and name check). |
| Port / Service | Server port or service name. |
| Connections | Number of parallel connections opened by **Connect**. |
| Connect | Builds a new TLS config snapshot from the settings and the address, then opens the connections. |
| Disconnect | Graceful disconnect of all connections (close_notify + FIN), then teardown. |
| Data | Message text. Each repetition is sent as `"<n> - <text>"` plus a terminating zero. |
| Repetitions, Send | Sends the message n times on every connection. |
| Send without delimiter | Omits the terminating zero, so the server cannot consume the data (receive limit test). |
| Raw TCP handshake trickle | Selected before **Connect**: the connections are plain TCP without TLS. After connecting a TLS record header announcing 512 bytes is sent, then the main window timer sends one byte per trickle interval (handshake timeout test). |
| Pause rcv / Resume rcv | `PauseReceive` / `ResumeReceive` on all client connections. |
| Abort (RST) | Abortive close of all client connections. |

---

## Settings

**File > Settings** edits a working copy. **OK** validates all fields and stores them in
`NetComTLSClient.ini` (next to the executable, section `[Settings]`). **Defaults** resets the
dialog to the built-in defaults.

| Dialog field | INI key | Default | Applies |
|---|---|---|---|
| TLS 1.0 / 1.1 / 1.2 / 1.3 | `Protocols` (bits 1/2/4/8) | 12 (TLS 1.2 + 1.3) | next Connect |
| Send client certificate if requested | `MutualAuth` | 1 | next Connect |
| Verify server name | `VerifyServerName` | 1 | next Connect |
| Target name | `TargetName` | empty (= address from the Send dialog) | next Connect |
| Certificate: Search by | `CertSearch` (1 subject, 2 serial, 3 thumbprint) | 1 | next Connect |
| Certificate: Value | `CertValue` | `ObjAsm Test Client` | next Connect |
| Certificate: Scope | `CertScope` (0 current user, 1 local machine) | 0 | next Connect |
| Certificate: Store | `CertStore` | `MY` | next Connect |
| Algorithms | `Ciphers` (ALG_ID hex list) | empty | next Connect |
| Inactivity timeout [s] | `InactivityTimeout` | 60 | immediately |
| Handshake timeout [s] | `HandshakeTimeout` | 15 | immediately |
| TLS shutdown timeout [s] | `TLSShutdownTimeout` | 5 | immediately |
| Receive pause timeout [s] | `RcvPauseTimeout` | 60 | immediately |
| Receive limit [KB] | `RcvLimitKB` | 1024 | immediately |
| Trickle interval [s] | `TrickleInterval` | 3 | immediately |

Notes:

- **Client certificate**: the provider is only created when *Send client certificate if
  requested* is set. It is used only if the server asks for a certificate. Without it, a server
  that requires mutual authentication rejects the handshake.
- **Target name / name check**: with *Verify server name* the name must match the server
  certificate. The test server certificate is issued for `ObjAsm TLS Test`, `localhost` and
  `127.0.0.1`. Without a target name the address from the Send dialog is used.
- **Timeouts**: 0 disables a timeout, maximum 429 s (NetCom stores 100 ns units in a DWORD).
- **Receive limit**: the client consumes zero-terminated messages; data without a terminator
  counts against the limit.
- **Certificate value, store and algorithms**: see the server README. The algorithm list shows
  the ALG_IDs SChannel offers on this host; SChannel restricts only the classes that contain a
  selected entry.

---

## Test scenarios

| # | Scenario | Steps | Expected |
|---|---|---|---|
| 1 | Handshake | Connect to the server. | `#Handshakes ok` +1; protocol, algorithms and server certificate in DebugCenter. |
| 2 | Echo | Send with server echo on. | `#Messages` increases by repetitions x connections. |
| 3 | Untrusted server | Use a server certificate whose CA is not trusted, or a wrong target name. | `#Handshakes failed` +1, error `TLS_CERTIFICATE_INVALID`. |
| 4 | Mutual authentication | Server requires a client certificate; client with / without *Send client certificate*. | Handshake ok / failed. |
| 5 | Protocol / algorithms | Restrict TLS versions or algorithms here or on the server. | Negotiated parameters change or `SEC_E_ALGORITHM_MISMATCH`. |
| 6 | Server receive limit | Server limit e.g. 64 KB; *Send without delimiter* with enough repetitions. | The server aborts the connection. |
| 7 | Handshake timeout | *Raw TCP handshake trickle*, Connect. | The server closes the connection after its handshake timeout, although bytes keep arriving. |
| 8 | Client receive pause | Server echo on, **Pause rcv**, send a lot. | `#Paused connections` > 0; the server's sends back up (`echo dropped` on the server). **Resume rcv**: the messages arrive. Without resume the client aborts after its pause timeout. |
| 9 | Load | Many connections, many repetitions. | Stable counters, no growing `#IOJobs` after the transfer. |
| 10 | Close | Disconnect vs. Abort. | Server sees close_notify + FIN vs. RST. |

---

## Implementation notes

- **TLS config snapshots.** `Connect` calls `NetComTLSClientProtocol.Reconfigure` with the
  server address. It builds a new `TLS_Connection_Config` (protocols, ALG_IDs, name check,
  target name) and, if required, a `TestCertProv` for the client certificate, then switches the
  protocol's `pTLSConfig`. Running connections keep their old snapshot. Old snapshots are kept in
  the `Graveyard` collection until the protocol is finalized after `NetComEngine.Done`. The
  shared config is never mutated while connections use it.
- **Raw mode.** `bRawMode` on the protocol template (set from the Send dialog at Connect) makes
  `Allocate` skip the TLS context. NetCom then handles the connection as plain TCP;
  `OnConnected` sends the TLS record header and the main window timer
  (`TestConnectionsAction(TTA_TRICKLE)`) sends the following bytes.
- **UI thread vs. worker threads.** Protocol callbacks run in IOCP worker threads. They update
  the statistics with `lock` instructions and post `WM_NETCOM_ENABLE_CTRLS` to the Send dialog
  instead of touching controls. Connection actions from the UI use `TryEnterCriticalSection`
  per connection and skip busy connections.
- **Sending.** The Send button holds the connection pool lock and calls `QueueSend` on every
  connection. With send backpressure (`NCC_SND_PAUSED`) `QueueSend` queues less than requested;
  the client does not retry.

---

## Limitations

- The address list only contains IPv4 addresses (`INTERNET_PROTOCOL_VERSION equ 4`).
- Timeouts are limited to 429 s.
- The library uses `SCHANNEL_CRED`: cipher restrictions work on ALG_IDs, not on named cipher
  suites. Windows 10 SChannel does not negotiate TLS 1.3.
- Messages are counted, not compared with the sent data.
- The client GUI features (settings dialog, test options, pause/resume, abort) have been built
  but not yet exercised systematically.

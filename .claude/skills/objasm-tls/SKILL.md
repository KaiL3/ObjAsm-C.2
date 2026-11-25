---
name: objasm-tls
description: Knowledge base for the ObjAsm TLS/SChannel layer of the NetCom framework (TLS_Context, TLS_SChannelContext, TLS_Connection_Config, TLS_CertValidator / TLS_DefaultCertValidator, TLS_CertProvider and the client/server cert providers, plus the TLS paths in NetComConnection such as OnReceivedTLS, QueueSendTLS, FlushPendingTLS, DeliverPlaintext, ApplyTLSConfig). Use this skill whenever you review, debug, extend or use TLS in ObjAsm - handshake, SNI, renegotiation / TLS 1.3 post-handshake messages, close_notify shutdown, certificate validation, mutual auth, SSPI calls (AcquireCredentialsHandle, InitializeSecurityContext, AcceptSecurityContext, EncryptMessage, DecryptMessage), SECBUFFER_EXTRA handling, SEC_E_/SEC_I_ status codes, or building an HTTPS/TLS client or server on NetCom. Also use it when the user mentions schannel.inc, sspi.inc or wincrypt.inc changes for TLS. Load the general `objasm` skill too for language/build conventions.
---

# ObjAsm TLS (SChannel) layer

TLS is an optional per-connection layer inside NetCom: a `NetComConnection` with
`pTLSContext != NULL` routes all received bytes through the TLS state machine and encrypts all
application sends. The implementation is SChannel/SSPI (`TLS_SChannelContext`), behind the abstract
`TLS_Context` interface. Read `references/architecture.md` for the full data flow before changing
receive/send code - most past bugs were ordering, buffer-ownership or state-transition bugs.

## Files and object hierarchy (`Code/Objects`)

| File | Role |
|---|---|
| `TLS_Context.inc` | Abstract base (Primer): state constants `TLS_STATE_*`, search constants, TLS error codes (`AddErrMsg`, base 111111130), `SP_PROT_*` fallbacks, config setters, shared reassembly-buffer fields |
| `TLS_SChannelContext.inc/.asm` | SChannel implementation: credentials, ISC/ASC handshake, Encrypt/Decrypt, shutdown, peer validation, buffers |
| `TLS_Connection_Config.inc` | Shareable config container (target name, protocols, cipher ALG_IDs, validator, providers, verify-name, mutual auth). Included by `NetCom.inc` |
| `TLS_CertValidator.inc` | Abstract validator: `Validate(pCert, pszServerNameA)`, `ValidateClient(pCert)` |
| `TLS_DefaultCertValidator.inc` | CertGetCertificateChain + CERT_CHAIN_POLICY_SSL, EKU check, hostname check, fail closed, **no revocation check** |
| `TLS_CertProvider.inc` | Shared store lookup `FindCert` (subject / thumbprint / serial; verifies private key) |
| `TLS_ClientCertProvider.inc`, `TLS_ServerCertProvider.inc` | Abstract `GetClientCert` / `GetServerCert(pSNIA, dLen)` |
| `TLS_DefaultClientCertProvider.inc`, `TLS_DefaultServerCertProvider.inc` | CurrentUser\MY resp. LocalMachine\MY lookup |
| `NetComConnection.inc` | TLS hooks: `Admit` (server start), `OnConnected` (client start), `OnReceived` -> `OnReceivedTLS`, `QueueSend` (state switch), `QueueSendTLS`, `QueueSendRaw`, `FlushPendingTLS`, `DeliverPlaintext`, `Disconnect` (close_notify), `ApplyTLSConfig` |
| `NetComProtocol.inc` | Callbacks `OnConfigureTLS`, `OnHandshakeComplete`, `OnHandshakeFailed` |
| `NetComSupervisor.inc` | TLS shutdown timeout (`dTLSShutdownTimeout`, 5 s) |
| `Code/Inc/Windows/sspi.inc`, `schannel.inc`, `wincrypt.inc` | API declarations (A and W variants!) |

Inheritance: `Primer -> TLS_Context -> TLS_SChannelContext`; `Primer -> TLS_CertProvider ->
TLS_Client/ServerCertProvider -> TLS_Default...`; `Primer -> TLS_CertValidator ->
TLS_DefaultCertValidator`. Library order is in `Code/Objects/Build/ObjectsX.lst`
(`TLS_CertValidator, TLS_CertProvider, TLS_Client/ServerCertProvider, TLS_Context, ...`).

## Invariants - do not break these

1. **One thread per connection at a time.** `NetComEngine.WorkerJob` enters the connection
   `CritSect` before every completion, and only one WSARecv is outstanding (the next one is posted
   inside the critical section). Application-thread entry points (`QueueSend`, `Disconnect`) enter
   the same recursive CritSect. Every new TLS entry point must do the same.
2. **Receive order comes from `RcvIOJobChain`**, not from completion order. `OnReceivedTLS` drains
   only consecutive IOJobs flagged `IOF_JOB_COMPLETED` into the reassembly buffer.
3. **Reassembly buffer ownership.** `pReassemblyBuffer/dReassemblyUsed` belong to the context but are
   filled by `NetComConnection`. `Decrypt` returns plaintext *inside* this buffer and records any
   SECBUFFER_EXTRA in `pDeferredExtra`; the caller must consume the plaintext and **then** MemShift
   the extra data. Handshake EXTRA is computed from the end of the input (`KeepExtra`, ISC/ASC do
   not set pvBuffer) and must be kept **before** `AllocateBuffers` may reallocate.
4. **Encrypt buffer is reused** - send/copy the output before the next `Encrypt`. Plaintext per
   record must be `<= dMaxMessageSize` (`QueueSendTLS` fragments).
5. **Application data is never sent in clear.** `QueueSend`: DATA -> encrypt; NONE/HANDSHAKE ->
   `PendingSendChain` (flushed by `FlushPendingTLS` when the state becomes DATA, also after
   renegotiation); SHUTDOWN/ERROR -> rejected (returns 0). Only SSPI tokens use `QueueSendRaw`.
6. **Target name is always ANSI** (`StrNewA`/`StrW2NewStrA`), therefore the SSPI calls are the
   explicit `...A` variants (`InitializeSecurityContextA`, `AcquireCredentialsHandleA`,
   `QueryContextAttributesA`) in every string build. Keep it that way.
7. **Fail closed.** Client: `ISC_REQ_MANUAL_CRED_VALIDATION`, so SChannel validates nothing;
   `ValidatePeer` requires a certificate, a validator and (with `bVerifyServerName`) a target name.
   Server with `bMutualAuth`: `ASC_REQ_MUTUAL_AUTH` (= 2; `20000h` would be ASC_REQ_INTEGRITY) and
   `ValidateClient`. Never turn a validation error into success.
8. **Certificate contexts**: providers return a context the caller frees; SChannel keeps its own
   reference after `AcquireCredentialsHandle`, so `CertFreeCertificateContext` right after it.
9. **Protocol callbacks** (`IsDataComplete?`, `ProcessData`, `OnHandshake*`, `OnError`) run inside
   TLS code: they must preserve `xbx/xsi/xdi` (use `uses`) and may call `QueueSend`/`Disconnect`
   (recursive CritSect) but must not touch the reassembly buffer.

## Using TLS in an application (checklist)

NetCom does **not** create or free TLS contexts. In the protocol object:
- `Allocate(pConn)`: `New TLS_SChannelContext`, **`OCall xax::TLS_SChannelContext.Init, pConn`**,
  store it in `[pConn].pTLSContext`. (Allocate runs in `NetComConnection.Init`, i.e. before
  accept/connect.) `New` only copies the template: without `Init` there is no default validator,
  and every client handshake ends in `TLS_CERTIFICATE_INVALID` (111111134) after a successful
  SSPI handshake - seen in the TLS Test client on 2026-10-12. If `New` fails, **return an error
  code** (and free what Allocate already allocated): the connection is then discarded. Returning 0
  without a context runs the connection in plaintext (O16).
- `OnConfigureTLS(pConn)`: return a shared `TLS_Connection_Config` (or NULL for context defaults).
  The config must **outlive every connection**: the context stores the cipher-suite pointer, it
  does not copy it, and credentials may be re-acquired later.
- Server: set a `TLS_ServerCertProvider` (config or context); client: `SetTargetName` for SNI and
  hostname validation (otherwise the handshake fails closed while `bVerifyServerName` is TRUE).
- Read received plaintext from **`[pConn].PlaintextChain`**, not `RcvIOJobChain` (that one holds
  ciphertext on TLS connections). Existing sample protocols scan `RcvIOJobChain` - they are not
  TLS-ready as they are.
- `Release(pConn)`: `Destroy [pConn].pTLSContext` and clear the pointer.
- Run the engine **with a `NetComSupervisor`**: TLS shutdown timeout, TLS handshake timeout
  (`dHandshakeTimeout`, initial handshake only, counted from StartTime) and inactivity timeout live
  there; without it a peer that never answers close_notify keeps the connection forever. Since
  NetComSupervisor C.1.1 accepted server connections are supervised too, so a server needs a
  sensible `dInactivityTimeout` (default 10 s) set on the template before `NetComEngine.Init`.
- Receive limit: `NetComProtocol.dMaxRcvBuffered` (default 1 MB, 0 = off) caps the unconsumed bytes
  per connection (RcvIOJobChain + PlaintextChain); exceeding it aborts the connection with
  `OnError(NCCN_RCV_LIMIT_EXCEEDED)`. Set it on the protocol (template or instance) to at least the
  largest message the protocol has to buffer.
- Flow control (legitimate slow consumer, e.g. proxy): `PauseReceive` / `ResumeReceive` on the
  connection - never set `NCC_RCV_PAUSED` directly. While paused no WSARecv is posted (TCP zero
  window throttles the peer), peer FIN/RST is seen only after resume, the supervisor applies
  `dRcvPauseTimeout` instead of the inactivity timeout; `Disconnect` lifts the pause.
- Link `Secur32.lib`, `Crypt32.lib`, `schannel.lib` (SslGetServerIdentity); include
  `WinSock2.inc`, `wincrypt.inc`, `sspi.inc`/`schannel.inc`. Object order: see `TLS_SChannelContext.asm`.

## Reviewing or changing TLS code

- Start from `references/known-issues.md`: it lists what was already analysed, what was fixed and
  what is still open, with the reasoning. Update it when you fix or find something.
- For any SSPI call, check: input/output SecBuffer types, `*_REQ_ALLOCATE_MEMORY` + `FreeContextBuffer`,
  EXTRA handling, the A/W variant, and every SEC_I_ status (CONTINUE_NEEDED, INCOMPLETE_CREDENTIALS,
  RENEGOTIATE, CONTEXT_EXPIRED) and SEC_E_INCOMPLETE_MESSAGE.
- Trace each error path to: state `TLS_STATE_ERROR`, `dLastError` = original status,
  `OnHandshakeFailed`/`OnError` once, `Disconnect`. No leaked tokens, cert contexts or IOJobs.
- Check every return code from ISC/ASC/ACH/QueryContextAttributes before using output.
- In 64-bit `invoke`, do not pass `eax`/`xax` as an argument when a later stack argument is a memory
  operand - the assembler may load it through `rax` first. Use a local (see `TLS_CertProvider.FindCert`).
- Source files contain CP1252 bytes (`TLS_SChannelContext.inc`, `NetComConnection.inc`): edit
  byte-exactly (Edit tool only for ASCII files; otherwise a Latin-1 round trip script).

## Verifying

TLS test programs: `Projects/X/NetCom/TLS Test` (server + client, untracked in git as of 2026-11-25).
Since 1.1.0 both have File > Settings (TLS versions, ciphers, mutual auth, certificate search,
timeouts, receive limit; stored in `<exe>.ini`), shared code in `TLS_TestCommon.inc` /
`TLS_TestSettingsDlg.inc/.rc`, server echo + Actions menu (pause/resume/disconnect/abort), client
test options (no delimiter, raw handshake trickle). The server can be driven headless from
PowerShell with `System.Net.Security.SslStream` (accept-all callback): handshake + echo, trickle
(raw `16 03 01 02 00` then 1 byte/s), receive limit (write MBs without ZTC, then wait and Read to
see the RST); write `RcvLimitKB=` etc. into the INI before starting the exe and delete it after.
Cipher restriction (`SetCipherSuites` -> `SCHANNEL_CRED.palgSupportedAlgs`, ALG_IDs): SChannel only
restricts the algorithm classes that appear in the list (tested 2026-11-25 on Windows 10: `6610`
alone -> AES 256 + SHA-384 + ECDHE; `660E, 800C, 800D, AE06, 2400, A400` -> AES 128 + SHA-256).
The host list comes from `QueryCredentialsAttributes(SECPKG_ATTR_SUPPORTED_ALGS)`; CryptFindOIDInfo
has no names for AES/SHA-2/ECDHE/ECDSA ALG_IDs.
Minimum check after a change: assemble all TLS objects in all four variants with the repo as
`OBJASM_PATH`:

```bash
bash .claude/skills/objasm-tls/scripts/assemble_tls.sh "<scratch dir>"
```

The script assembles (no lib, nothing in the repo is touched) every TLS/NetCom object for
64W/64A/32W/32A into `<scratch dir>/<variant>` and prints the first errors per object.

Assembling proves syntax and macro expansion only. Behaviour needs a running client/server: test
against `openssl s_server`/`s_client` or `curl -v --resolve host:port:127.0.0.1`, including SNI with
a large ClientHello, mutual auth, peer close_notify, local Disconnect, and TLS 1.3 on Windows 11 /
Server 2022 (Windows 10 SChannel does not negotiate TLS 1.3).

## Debugging

- `dLastError` keeps the original SECURITY_STATUS/HRESULT; `TranslateError` maps common codes
  (strings are ANSI `db`). `OnHandshakeFailed(pConn, dLastError)` receives it too.
- `OnReceivedTLS` already has `DbgDec eax, "TLS State"` / `"DATA: ResBuf"` probes.
- Frequent codes: `80090318` SEC_E_INCOMPLETE_MESSAGE (need more data), `80090331`
  SEC_E_ALGORITHM_MISMATCH (protocol/cipher), `80090325` untrusted root, `800B010F` CN mismatch,
  `800B0109` untrusted root (validator), `80090327` cert unknown, `00090320`
  SEC_I_INCOMPLETE_CREDENTIALS (server wants client cert), `00090321` SEC_I_RENEGOTIATE,
  `00090317` SEC_I_CONTEXT_EXPIRED (peer close_notify).

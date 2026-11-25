# TLS review log - findings and status

Last full review: 2026-10-11 (branch `TLS`, on top of c26a37eb plus uncommitted work).
Security review NetCom/TLS: 2026-11-20 (static code review, nothing changed, nothing tested) -> O12-O20.
Keep this file current: add new findings, change the status when something is fixed, and say how it
was verified. "Assembled" means all four variants (32/64 x A/W) assemble; it does not mean tested.

## Fixed in the working tree (not yet committed at review time)

Earlier session (visible in `git diff`):
- Plaintext sent during the handshake is held in `PendingSendChain` and flushed encrypted
  (`QueueSendRaw`/`FlushPendingTLS`/`DeliverPlaintext` split out of `NetComConnection`).
- Server mutual authentication: `SetMutualAuth`, `ASC_REQ_MUTUAL_AUTH` corrected to `2`,
  `TLS_CertValidator.ValidateClient` + `AUTHTYPE_CLIENT` / client-auth EKU in the default validator.
- Peer validation fails closed (`ValidatePeer`): missing certificate, validator or target name =
  failure; validator errors are kept in `dLastError`.
- `TLS_Connection_Config.GetCertValidator` no longer references `TLS_DefaultCertValidator`
  (NULL = keep the context default set in `TLS_SChannelContext.Init`).
- `sspi.inc`: ANSI variants declared; `schannel.inc`: `SslGetServerIdentity` prototype types fixed;
  `TLS_SChannelContext.asm` includes `wincrypt.inc` and loads `TLS_DefaultCertValidator`,
  `TLS_CertProvider`; `ObjectsX.lst` contains `TLS_CertProvider`.
- Handshake EXTRA kept before `AllocateBuffers` (no use-after-free); client certificate retry
  limited to one attempt.

This session (2026-10-11):
- **SNI lost when the ClientHello spans several TCP segments** - `ProcessHandshakeData` evaluated
  `SslGetServerIdentity` and created the server credentials on the first data, even a partial
  ClientHello (common with post-quantum key shares, ~1.8 KB > MSS). Result: no SNI, wrong
  certificate for multi-host servers. Fix: wait until the first handshake record is complete
  (record header length), oversized lengths are passed on to ASC. Status: assembled; needs a live
  test with a large ClientHello (e.g. current Chrome/curl with ML-KEM) and `--resolve` SNI.
- **Certificate store opened for writing** - `TLS_CertProvider.FindCert` called `CertOpenStore`
  without `CERT_STORE_READONLY_FLAG`, which fails with ACCESS_DENIED for non-admin accounts
  (LocalMachine\MY for services). Now `READONLY | OPEN_EXISTING`, flags passed through a local
  (64-bit invoke register order). Status: assembled; test as a standard user.

## Open findings

| # | Severity | Finding | Suggested fix |
|---|---|---|---|
| O1 | Medium | In TLS_STATE_SHUTDOWN all received bytes are discarded and the first arrival is treated as the peer's close_notify. Application data still in flight (e.g. a response after a client did `Disconnect(SD_SEND)` = half-close) is lost silently. | Keep decrypting in SHUTDOWN until `SEC_I_CONTEXT_EXPIRED`, deliver plaintext for half-close; only then `shutdown(SD_SEND)`. |
| O2 | Medium (verify) | Credentials use `SCHANNEL_CRED` v4 with `SP_PROT_TLS1_3` in the default mask. Microsoft documents TLS 1.3 only for `SCH_CREDENTIALS` (+ `TLS_PARAMETERS`); on Windows 11 / Server 2022 this may fall back to TLS 1.2 or fail in AcquireCredentialsHandle. Windows 10 SChannel has no TLS 1.3, so tests there cannot show it. | Test on Win11/2022; migrate to `SCH_CREDENTIALS` (`SCH_CREDENTIALS_VERSION` 5, `pTlsParameters->grbitDisabledProtocols`); cipher restriction moves to `TLS_PARAMETERS`/`CRYPTO_SETTINGS`. |
| O3 | Low (latent) | Note 2026-10-12: `NCC_SND_PAUSED` is currently **never set** anywhere (only tested and cleared in `OnSent`); `dSndHighWtrMrk` is unused, so send backpressure does not exist yet and this cannot happen today. It becomes real once the high-water mark is implemented. `SendToken` -> `QueueSendRaw` stops while `NCC_SND_PAUSED` is set; the SSPI token is then freed unsent. Under send backpressure a renegotiation / post-handshake reply or the close_notify can be lost (stall or unclean close). | Let token sends bypass the pause check (they are small and mandatory), as `FlushPendingTLS` already does for accepted data. |
| O4 | Low | Handshake can stall: if the reassembly buffer is full and SChannel still returns `SEC_E_INCOMPLETE_MESSAGE`, no progress is possible; `SECBUFFER_MISSING` is ignored. | Detect "buffer full + no progress" and fail the handshake (or grow the buffer). |
| O5 | Low | No handshake timeout. Shutdown timeout and inactivity timeout only run in `NetComSupervisor`; without a supervisor a silent peer keeps a connection (and its 18 KB buffer + credentials) forever. | Document "supervisor required for TLS"; optionally a handshake deadline. |
| O6 | Low | `TLS_Context.SetAllowedCipherSuites` stores the caller's pointer (no copy). Credentials are acquired later (server: on ClientHello; client: on INCOMPLETE_CREDENTIALS), so the config must outlive all connections. `TLS_Connection_Config.SetCipherSuites` silently drops the restriction if MemAlloc fails (fail open). | Copy the array into the context; report the allocation error. |
| O7 | Info (verify) | Responding to a peer close_notify calls ISC/ASC without `ApplyControlToken(SCHANNEL_SHUTDOWN)` (state already SHUTDOWN). Check with a capture that our close_notify is really sent. | If not, always apply the control token before generating the shutdown token. |
| O8 | Info | No certificate revocation check (`CertGetCertificateChain` dwFlags = 0). | Optional `CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT` behind a config switch. |
| O11 | Fixed 2026-10-12 (test apps) | `Projects/X/NetCom/TLS Test` (untracked): client and server `Allocate` did `New TLS_SChannelContext` without `Init` -> no default validator -> client fails with `TLS_CERTIFICATE_INVALID` (111111134) after a complete SSPI handshake. Added `OCall xax::TLS_SChannelContext.Init, xbx`; client `OnHandshakeFailed` now prints `dError` (= dLastError). | Assembled (0 errors); link/run pending (exes were running). Consider making a missing validator impossible, e.g. `ValidatePeer` falling back to the default template, or asserting in Debug builds. |
| O9 | Gap | `Projects/X/NetCom/TLS Test` exists but is untracked (not in git); older sample protocols (`NetComCoreServer_Protocol`, `NetComStressServer_Protocol`, `SRPS_Protocol`) read `RcvIOJobChain`, which holds ciphertext on TLS connections. | Add a TLS echo client/server sample that reads `PlaintextChain`; maybe a protocol helper returning the right chain. |
| O12 | High - **fixed in working tree 2026-11-20** (NetComSupervisor C.1.1: skip only pending acceptors, busy connection -> `jmp @@Next` instead of restarting the traversal, `dHandshakeTimeout` 15 s from StartTime while `TLS_Context.bHandshakeDone == FALSE` -> OnHandshakeFailed/OnError(TLS_HANDSHAKE_TIMEOUT) + abortive close; `bHandshakeDone` moved to TLS_Context; LastTime typo fixed; test servers set dInactivityTimeout 60 s. Assembled 4 variants, libs rebuilt, Core/TLS servers + TLS client built; **tested 2026-11-25** against the TLS Test server (SslStream from PowerShell): raw trickle closed after 15.1 s; SRPS supervisor copy still has the old skip). Original finding: | `NetComSupervisor.WorkerJob` skips every connection with `NCC_QUEUE_ACCEPT or NCC_ACCEPTED` set (`.ifBitClr` = all bits clear). Both flags are never cleared, so **every server-side connection** is excluded from the inactivity timeout and the TLS shutdown timeout. A client that connects and never sends a ClientHello (or never answers close_notify) holds the connection, the 18 KB reassembly buffer and later the SSPI context forever (slowloris). Makes O5 worse: a supervisor does not help servers. | Skip only pending acceptors: `(dFlags and (NCC_QUEUE_ACCEPT or NCC_ACCEPTED)) == NCC_QUEUE_ACCEPT`. Add a handshake deadline (StartTime based) independent of LastTime. |
| O13 | High - **partly fixed in working tree 2026-11-20** (`NetComProtocol.dMaxRcvBuffered`, default `RCV_LIMIT_DEFAULT` = 1 MB, 0 = no limit; `NetComConnection.CheckRcvLimit` runs after every data receive (plain path and after OnReceivedTLS), counts completed IOJobs in RcvIOJobChain + PlaintextChain (counted, not a running total, because SRPS consumes the chain itself), on excess OnError(NCCN_RCV_LIMIT_EXCEEDED) + QueueDestroy + Close(TRUE). Assembled 4 variants, libs rebuilt, TLS server/client + Core server built; **tested 2026-11-25** (TLS Test server, 2 MB without delimiter): RcvLimitKB=0 stays open, 64 KB and 1024 KB -> RST. Pause/resume not run yet. Receive flow control added the same day: `NetComConnection.PauseReceive/ResumeReceive` (NCC_RCV_PAUSED honoured by OnReceived and QueueReceive; QueueReceive posts at most one receive and runs under the CritSect; ResumeReceive refreshes LastTime and does not post after a peer FIN / local SD_RECEIVE; Disconnect (not SD_RECEIVE) lifts a pause; Close ignores it), `PauseTime`, supervisor `dRcvPauseTimeout` 60 s -> OnError(NCCN_RCV_PAUSE_TIMEOUT) + abort, no inactivity timeout while paused. SRPS supervisor C.1.1 uses the API (its own WorkerJob copy has no pause timeout and still the old O12 skip). Built incl. SRPS, not run. Still open: no global IOJob cap, O(n^2) rescans in the sample protocols, ResumeReceive does not re-run ProcessData on data already in the chain (SRPS can stall if the last chunk was not forwarded and the peer sends nothing more - pre-existing). Original finding: | No receive limit. `OnReceived` re-posts WSARecv before processing; `NCC_RCV_PAUSED` is not used by the library; `NetComIOJobPool` grows without a cap. `PlaintextChain` (TLS) / `RcvIOJobChain` (plain) grow as long as `IsDataComplete?` returns 0 -> a peer streaming data without a delimiter exhausts memory. Sample protocols rescan the whole chain per IOJob (O(n^2) CPU). Same for RcvIOJobChain when the TLS reassembly stalls (O4). | Per-connection max buffered bytes (fail with ERROR_BAD_PROTOCOL / disconnect), stop re-posting WSARecv above a high-water mark, optional global IOJob cap. |
| O14 | Medium (found 2026-11-20) | Mutual auth accepts **any** client certificate that chains to any root in the machine trust store and has the clientAuth EKU (`ValidateClient` = chain + EKU only). No issuer restriction, no API to hand the client certificate / identity to the protocol for authorization. Server credentials lack `SCH_CRED_NO_SYSTEM_MAPPER` (SChannel tries Windows account mapping). | Validator with exclusive root store (`CERT_CHAIN_ENGINE_CONFIG.hExclusiveRoot`) or issuer/thumbprint allow-list; method to query the peer certificate after OnHandshakeComplete; set NO_SYSTEM_MAPPER. |
| O15 | Medium (found 2026-11-20) | Truncation not detectable: FIN without close_notify in TLS_STATE_DATA (and in HANDSHAKE) is reported as a normal disconnect with `dDisconnectError = NO_ERROR`; a partial record in the reassembly buffer is dropped silently; no OnHandshakeFailed for FIN during the handshake. Protocols that frame by connection close can be truncated by an attacker. | Report a distinct error (e.g. new TLS_TRUNCATED) when FIN arrives before SEC_I_CONTEXT_EXPIRED; OnHandshakeFailed for FIN in HANDSHAKE. |
| O16 | Medium (design, found 2026-11-20) | TLS is enabled only by `pTLSContext != NULL`. If `Allocate` fails to create the context (the TLS Test server logs a warning and returns 0), the connection silently runs **in plaintext** (fail open). | Make Allocate fail, or add a "TLS required" flag in the protocol that Admit/OnConnected check. |
| O17 | Medium (verify, found 2026-11-20) | Connection lifetime vs. application threads: `QueueSend`/`Disconnect` read `pTLSContext` before the CritSect; destruction does FreeRessources -> Leave -> `Done` (DeleteCriticalSection) -> pool reuse. A stale connection pointer used after OnClosed hits a deleted CritSect or, after reuse, sends data to a **different peer**. | Generation counter / connection ID check or reference counting; document "no use after OnClosed". |
| O18 | Low (found 2026-11-20) | Shared `TLS_Connection_Config` is mutated without synchronisation (TLS Test client: UI thread calls SetTargetName while workers run ApplyTLSConfig -> GetTargetName; SetTargetName frees the old string) -> possible use-after-free. | Treat config as immutable after start or protect it with a lock. |
| O19 | Low (found 2026-11-20) | `Shutdown` ignores the ISC/ASC status; `Disconnect` ignores the Shutdown result. ApplyControlToken failure -> state ERROR but NCC_TLS_SHUTDOWN_PENDING set and no TCP shutdown until the timeout (never for servers, O12). Supervisor inactivity path does Disconnect(SD_SEND) and immediately Close(TRUE) (RST), so the close_notify is usually lost. Inactivity check tests `dwLowDateTime` twice (typo). | Check results, fall back to TCP shutdown on failure; fix the typo. |
| O20 | Low (found 2026-11-20) | Certificate selection: `CERT_FIND_SUBJECT_STR` is a substring match, first hit wins, no validity/EKU filter; serial search ignores the issuer. SNI passed to GetServerCert is attacker controlled, not NUL-terminated and points into the reassembly buffer. Credentials + store lookup per ClientHello = CPU amplification (see O10). | Prefer thumbprint; filter by NotAfter and serverAuth EKU; document SNI contract; cache server credentials per SNI. |
| O10 | Cosmetic | `TLS_Connection_Config.bValidatorIsSet` is unused; `TranslateError` returns ANSI strings in WIDE builds; credentials are acquired per connection (cost per handshake). | Clean up when touching the files. |

## Checked and found OK (do not re-investigate without new evidence)

- Receive ordering / concurrency: completions run under the connection CritSect and only one WSARecv
  is outstanding, so FIN handling and `OnReceivedTLS` cannot race each other.
- `NetComConnectionPool.NewItem` re-creates connections from the template (`New`), so a stale
  `pTLSContext` cannot survive pool reuse.
- `Decrypt` EXTRA handling via `pDeferredExtra` after `DeliverPlaintext`; handshake EXTRA via
  `KeepExtra` (computed from the input end).
- `TLS_DefaultCertValidator` is stateless and safe to share; hostname conversion fails closed.
- String types in `wincrypt.inc` (`CERT_STORE_PROV_SYSTEM`, `CERT_FIND_SUBJECT_STR`) follow
  `TARGET_STR_TYPE`, matching the `CStr` store name.

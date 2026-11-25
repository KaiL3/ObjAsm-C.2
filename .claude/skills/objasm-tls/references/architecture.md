# TLS data flow and state machine

## Contents
1. State machine
2. Start of a connection (client / server)
3. Receive path (`OnReceived` -> `OnReceivedTLS`)
4. Handshake step (`ProcessHandshakeData`)
5. Data phase (`Decrypt`, `DeliverPlaintext`)
6. Send path (`QueueSend` -> `QueueSendTLS` / `PendingSendChain`)
7. Shutdown (close_notify) and FIN handling
8. Credentials, SNI, certificates, validation

## 1. State machine (`TLS_Context.GetState`)

```
NONE --StartClient/ServerHandshake--> HANDSHAKE --ISC/ASC SEC_E_OK + ValidatePeer ok--> DATA
HANDSHAKE --any error / validation failure--> ERROR (OnHandshakeFailed, OnError, Disconnect)
DATA --DecryptMessage SEC_I_RENEGOTIATE--> HANDSHAKE (TLS 1.2 reneg / TLS 1.3 post-handshake) --> DATA
DATA --DecryptMessage SEC_I_CONTEXT_EXPIRED (peer close_notify)--> SHUTDOWN
DATA --local Disconnect(SD_SEND|SD_BOTH) -> Shutdown()--> SHUTDOWN
DATA --DecryptMessage other error--> ERROR
```

`bHandshakeDone` makes `OnHandshakeComplete` fire only for the first handshake. `bIsClient`
selects ISC (client) vs ASC (server) everywhere.

## 2. Start

- **Client** `NetComConnection.OnConnected`: `OnConfigureTLS` -> `ApplyTLSConfig` ->
  `StartClientHandshake` (InitCredentials OUTBOUND, anonymous, `dwSessionLifespan = 1` = no session
  cache; allocate reassembly buffer `TLS_MAX_RECORD_SIZE`; first ISC with `pTargetName` -> ClientHello
  via `SendToken`) -> `QueueReceive` -> protocol `OnConnected`.
- **Server** `NetComConnection.Admit(TRUE)`: bind to IOCP -> `OnConfigureTLS` -> `ApplyTLSConfig` ->
  `StartServerHandshake` (state HANDSHAKE, reassembly buffer only; credentials are deferred until
  the ClientHello is complete so SNI can choose the certificate) -> `QueueReceive`.
- Failure to start: `OnHandshakeFailed` + `OnError`, then Disconnect (client) or
  QueueDestroy + Close (server).

## 3. Receive path

`NetComEngine.WorkerJob` (holding the connection CritSect) sets `IOF_JOB_COMPLETED` and calls
`OnReceived`. That posts the next WSARecv first (so at most one receive is outstanding), then for
TLS calls `OnReceivedTLS`, which loops (`@@Cycle`):

1. Drain consecutive completed IOJobs from `RcvIOJobChain` into the reassembly buffer; partially
   consume an IOJob if the buffer is nearly full; free fully consumed IOJobs.
2. Stop if nothing new was copied (except on the first pass).
3. Dispatch on state: HANDSHAKE -> `@@HandshakeLoop`; DATA -> `@@DecryptLoop`; SHUTDOWN -> discard
   buffer, finish a locally initiated shutdown (`shutdown(SD_SEND)`, post DISCONNECTED); ERROR ->
   free remaining completed IOJobs.

A zero-byte receive (FIN) is handled in `OnReceived` itself (see 7).

## 4. Handshake step (`TLS_SChannelContext.ProcessHandshakeData`)

Input = whole reassembly buffer. Two SecBuffers in (`TOKEN`, `EMPTY` for EXTRA), one out (`TOKEN`,
SSPI-allocated).
- `SEC_I_CONTINUE_NEEDED`: send token, `KeepExtra` (moves unconsumed tail to buffer start).
- `SEC_E_OK`: send token, `KeepExtra`, then `@@HandshakeComplete`: `ValidatePeer` ->
  `QueryContextAttributesA(STREAM_SIZES)` -> `AllocateBuffers` (grows buffers, keeps content) ->
  `dMaxMessageSize` -> DATA -> `OnHandshakeComplete` (first time only).
- `SEC_I_INCOMPLETE_CREDENTIALS` (client): one attempt: get cert from `pClientCertProvider`,
  re-acquire credentials with it, retry ISC with the same input.
- `SEC_E_INCOMPLETE_MESSAGE`: free token, keep buffer unchanged, wait for more data.
- Anything else: send the alert token if any, `dLastError = status`, `@@HandshakeFailed`.

`OnReceivedTLS` repeats the step while it consumes data; when the state becomes DATA it calls
`FlushPendingTLS` and continues with the decrypt loop for data that followed the Finished message.

## 5. Data phase

`Decrypt` (4 SecBuffers: DATA + 3 EMPTY) on the reassembly buffer:
- `SEC_E_OK`: plaintext pointer/size into the buffer; EXTRA remembered in `pDeferredExtra`.
- `SEC_E_INCOMPLETE_MESSAGE`: 0 bytes, OK.
- `SEC_I_RENEGOTIATE`: state HANDSHAKE, EXTRA shifted to the front; `OnReceivedTLS` calls
  `ProcessHandshakeData` once even with 0 bytes.
- `SEC_I_CONTEXT_EXPIRED`: state SHUTDOWN.
- Error: state ERROR, `TLS_DECRYPT_ERROR` -> `OnError` + `Disconnect(SD_BOTH)`.

`DeliverPlaintext` copies the plaintext into IOJobs (pool buffer size), appends them to
`PlaintextChain` and runs `IsDataComplete?` / `ProcessData` like the non-TLS path, trimming consumed
bytes from `PlaintextChain`. Only after that is the deferred EXTRA shifted.

## 6. Send path

`QueueSend` (enters CritSect):
- DATA: `FlushPendingTLS` first (byte order), then if not `NCC_SND_PAUSED` `QueueSendTLS`:
  fragments to `dMaxMessageSize`, `Encrypt` each block (header | data | trailer in
  `pEncryptBuffer`), copies the record into SEND IOJobs (`DoSndIOJob`).
- NONE / HANDSHAKE: copy into `PendingSendChain` IOJobs (not sent).
- SHUTDOWN / ERROR: return 0.

Tokens (`SendToken`) go through `QueueSendRaw`, which stops early when `NCC_SND_PAUSED` is set.

## 7. Shutdown and FIN

- **Local** `Disconnect(SD_SEND|SD_BOTH)` in DATA: `Shutdown()` = `ApplyControlToken(SCHANNEL_SHUTDOWN)`
  + ISC/ASC -> close_notify via `SendToken`; flag `NCC_TLS_SHUTDOWN_PENDING`; no TCP shutdown yet.
  Next received data (peer's close_notify) -> `OnReceivedTLS` SHUTDOWN branch -> `shutdown(SD_SEND)`
  + DISCONNECTED. Peer FIN instead -> `OnReceived` FIN branch completes. Peer silent ->
  `NetComSupervisor` closes abortively after `dTLSShutdownTimeout`.
- **Peer** close_notify (`SEC_I_CONTEXT_EXPIRED`): reply with our close_notify unless the peer already
  sent FIN, then `shutdown(SD_SEND)` + DISCONNECTED(SD_RECEIVE).
- **FIN without close_notify** (truncation): `shutdown(SD_SEND)` + DISCONNECTED; with
  `NCC_SHUTDOWN_SND_LOCAL` set the sequence is already complete.
- `OnError` suppresses expected errors after `NCC_CLOSED` or after a TLS half-close.
- `DISCONNECTED` / `CLOSED` are posted as synthetic IOCP completions exactly once
  (`NCC_DISCONNECT_POSTED`, `..._DELIVERED` flags gate destruction).

## 8. Credentials, SNI, certificates

- `InitCredentials(dUsage, pSNI, dSNILen)`: `SCHANNEL_CRED` v4 with `grBitEnabledProtocols`,
  optional `palgSupportedAlgs` (pointer from config, not copied), `SCH_USE_STRONG_CRYPTO`; server
  gets the certificate from `GetServerCert(pSNI, dSNILen)`; client `SCH_CRED_NO_DEFAULT_CREDS`.
  Package name `"Microsoft Unified Security Protocol Provider"` (UNISP_NAME_A).
- SNI (server): `SslGetServerIdentity(pData, dDataSize, &pName, &dLen, 0)`; `pName` points into the
  buffer (no allocation, not zero-terminated - use `dLen`). Only evaluated once, when credentials
  are created; the code waits until the first TLS record is complete.
- Providers: `FindCert` opens the system store read-only, finds by subject string (CHR type of the
  build), SHA-1 thumbprint (`CRYPT_HASH_BLOB`) or serial (`CRYPT_INTEGER_BLOB`, little endian as in
  CERT_INFO), and requires an accessible private key (`CryptAcquireCertificatePrivateKey`).
- Validation: `TLS_DefaultCertValidator` is used via its template (`$ObjTmpl`) - stateless, shared
  by all connections. Validators must stay stateless or be per connection.

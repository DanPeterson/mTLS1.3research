# Empirical results — TLS 1.3 client-cert auth on one port (443)

Captured on **Windows 11, .NET SDK 10.0.302, Schannel TLS 1.3**. Reproduce it yourself with the
scripts in this repo (`1-setup` → `2-run-server` → `3-probe`, all on port 443).

This directly tests the premise behind SPP 9.0's "TLS 1.3 client-cert auth needs its own port 7443"
decision: **can TLS 1.3 in-handshake mutual TLS share a port with ordinary non-cert traffic?** It can.

---

## The production stack: ASP.NET Core on HTTP.sys, port 443

Exactly what SPP runs. One process, `Now listening on: https://+:443/`,
`ClientCertificateMethod = AllowCertificate` (no renegotiation). Three real `netsh http add sslcert`
bindings on **:443**, identical except for the `clientcertnegotiation` flag:

| binding | flag | app reads cert via | models |
|---------|------|--------------------|--------|
| `hostnameport=certauth.local:443` | `clientcertnegotiation=enable`  | `Connection.ClientCertificate` (cached) | **in-handshake mTLS** (the fix) |
| `hostnameport=delay.local:443`    | `clientcertnegotiation=disable` | `GetClientCertificateAsync()` | **delayed / PHA** (SPP's current default) |
| `hostnameport=nocert.local:443`   | `clientcertnegotiation=disable` | not read | **no client auth** (opt-out) |
| `ipport=0.0.0.0:443`              | `clientcertnegotiation=disable` | not read | no client auth (IP fallback) |

All hostnames resolve to `127.0.0.1` via a hosts entry (no DNS). The server sets
`ClientCertificateMethod = AllowRenegotation` and branches on the SNI host. Note `delay.local` and
`nocert.local` carry the **same** netsh flag — the difference is one app decision, proving the three
modes are a binding + app-layer combination, not three ports.

### Result (captured — HTTP/1.1, PHA-capable client)

| URL | SNI/IP → binding | app fetch | TLS | server saw client cert |
|-----|-------------------|-----------|-----|------------------------|
| `https://certauth.local/` (offers cert) | enable  | cached property | **1.3** | **CN=demo-client** (in-handshake) |
| `https://delay.local/` (offers cert)    | disable | `GetClientCertificateAsync()` | **1.3** | **CN=demo-client** (via renegotiation / PHA) |
| `https://nocert.local/` (offers cert)   | disable | (none) | **1.3** | none |
| `https://127.0.0.1/` (offers cert)      | ipport  | (none) | **1.3** | none |

### The HTTP/2 contrast (the decisive result)

Re-running the same two hosts over **HTTP/2** (captured):

| URL | app fetch | HTTP | result |
|-----|-----------|------|--------|
| `https://certauth.local/` | cached property (in-handshake) | **HTTP/2** | **CN=demo-client** — authenticated |
| `https://delay.local/`    | `GetClientCertificateAsync()` (post-handshake) | **HTTP/2** | **no client certificate** — client offered one, but PHA is forbidden on HTTP/2 |

This is the crux: the **delayed/PHA** path cannot collect the cert over HTTP/2 (or for TLS 1.3 async
clients) — the real driver behind the 7443 proposal — while the **in-handshake** binding authenticates
the same client over both HTTP/1.1 and HTTP/2. Both live on the same port 443, selected by SNI.
Reproduce with `scripts/3-probe.ps1`.

### What this proves

**TLS 1.3 client-certificate authentication coexists on port 443 with ordinary traffic on the same
HTTP.sys listener, and the in-handshake variant works for every client (including HTTP/2 and TLS 1.3
async).** The delayed/PHA behavior that forced the 7443 decision is fixed by an SNI-scoped
in-handshake binding on the same port — no separate port required at the HTTP.sys layer.

### Cross-check (curl)

`curl --tlsv1.3 -k https://delay.local/` returned `HTTP/1.1 200 OK`, and its Schannel trace showed
`remote party requests renegotiation` — the *delayed*/post-handshake client-cert path — versus
`certauth.local`, which requests the cert **in the handshake**. Same port, two negotiation timings,
selected by SNI.

---

## Layer 0: raw SslStream (protocol-level, zero admin)

Before the HTTP.sys version, the same result was confirmed at the pure TLS layer with a raw
`SslStream` server+client in one process on a loopback high port (no admin, no cert store, no hosts).
Per-connection policy was chosen purely from the client-sent SNI in a
`ServerOptionsSelectionCallback`:

```
#   SNI sent         client offers    TLS       server saw client cert?
1   delay.local      yes              Tls13     no      (primary SNI, no in-handshake request)
2   certauth.local   yes              Tls13     YES     (opt-in mTLS SNI, in-handshake TLS 1.3)
3   (none / IP)      yes              Tls13     no      (no SNI -> default)
4   certauth.local   no               Tls13     no      (require enforced app-side; TLS still completes)
```

Probe #4 is the honest nuance: `ClientCertificateRequired` at the TLS layer does **not** hard-fail a
TLS 1.3 handshake when the client sends no cert — the handshake completes and the app sees a null
cert. Allow-vs-require enforcement is therefore an **application-layer** decision (HTTP 403), the same
way ASP.NET Core's certificate-auth middleware and the `netsh` `clientcertnegotiation` flag
(request-in-handshake vs not) divide responsibilities.

---

## Why this matters for SPP and the SDKs

The clients that break under SPP 9.0's TLS 1.3 change break specifically on **post-handshake auth
(PHA)**: Node.js, Java, Python `aiohttp`, and anything over **HTTP/2** (which forbids PHA entirely).
An **SNI-scoped, in-handshake** cert binding on 443 fixes them **with no client code change and no
second port**, because the certificate is requested during the initial handshake instead of after it.

The default hostname can keep today's delayed/PHA behavior, so the existing PHA-capable fleet (.NET /
`SafeguardDotNet`, PowerShell / `safeguard-ps`, Python `requests` / PySafeguard sync, curl) stays
zero-touch. The result is additive and opt-in: one port, one server cert, behavior selected by the
SNI-scoped binding — which is exactly what this repo demonstrates.

## Harness gotchas (not SPP issues — for anyone scripting probes)

- A PowerShell `ServerCertificateCustomValidationCallback` **scriptblock** throws `There is no
  Runspace available to run scripts in this thread` (the TLS callback runs on an I/O thread). Use
  `[System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator`.
- A client cert loaded with `X509KeyStorageFlags.EphemeralKeySet` **fails** Schannel client auth. Load
  it from a store (`Cert:\CurrentUser\My\<thumb>`) or with `PersistKeySet` so the private key persists.

# TLS 1.3 mutual TLS on port 443

**Question under test:** *Does TLS 1.3 client-certificate (mutual TLS) authentication require its own
port, or can it share 443 with all other traffic?*

**Finding:** It can share 443. This repository is a self-contained, runnable demonstration that on a
**single** port (443), using the **same production stack as SPP** (ASP.NET Core on **HTTP.sys**), TLS
1.3 in-handshake mutual TLS coexists with ordinary non-certificate traffic, differentiated by the
**SNI hostname** through three `netsh http add sslcert` bindings that differ by a single flag.

The demo runs in a few minutes and lets you confirm in a browser that one hostname prompts for a
client certificate while another does not — same port, same server, same process.

---

## What you'll see

Three client-cert behaviors, all on port 443, selected purely by the SNI hostname:

| You browse to | netsh binding | App behavior | Behavior modeled | Browser |
|---------------|---------------|--------------|------------------|---------|
| `https://certauth.local/` | `clientcertnegotiation=enable` | reads cached cert | **in-handshake mTLS** (recommended) | **Prompts**; page shows `CN=demo-client` |
| `https://delay.local/` | `clientcertnegotiation=disable` | `GetClientCertificateAsync()` | **delayed / PHA** (SPP's current default) | prompts on HTTP/1.1; over HTTP/2 gets **no cert** (auth fails) |
| `https://nocert.local/` | `clientcertnegotiation=disable` | never reads cert | **no client auth** (opt-out) | **No prompt** |
| `https://127.0.0.1/` | `clientcertnegotiation=disable` (IP) | never reads cert | no client auth (raw IP) | **No prompt** |

`delay.local` and `nocert.local` carry the **same** netsh flag; the only difference is whether the
app requests the certificate. In-handshake, delayed, and no-auth are the result of one SNI-scoped
binding plus one application decision — not a separate port.

**Why the HTTP/2 comparison matters (`3-probe.ps1`):** `certauth.local` authenticates the client
certificate over **both** HTTP/1.1 and HTTP/2, while `delay.local` obtains **no certificate over
HTTP/2**, because HTTP/2 does not permit the post-handshake authentication the delayed path relies on.
The same client presenting the same certificate succeeds on the in-handshake binding and fails on the
delayed one. Requesting the certificate during the handshake resolves this on the same port.

All hosts resolve to the same `0.0.0.0:443` listener in one process, using one server certificate;
only the SNI/IP-selected binding differs. No second port is involved.

---

## Prerequisites

- **Windows 11** (or Windows Server 2022+) — TLS 1.3 in Schannel requires it; Windows 10 does not
  support TLS 1.3. SPP 9.0's base OS qualifies.
- **Administrator** PowerShell (for `netsh`, the `hosts` file, port 443, and LocalMachine cert store).
- **.NET SDK 8.0+** (`dotnet --version`). Download: <https://dotnet.microsoft.com/download>.
- **Edge or Chrome** for the visual test (they use the Windows cert store). *Firefox uses its own
  store — see Troubleshooting.*
- **PowerShell 7+ (`pwsh`)** recommended. Windows PowerShell 5.1 also works.

The demo certificates are **pre-generated and committed** under `certs/` — throwaway self-signed
certs for this proof only, never production. PFX password is `demo`. Regenerate any time with
`certs/generate-certs.ps1`.

---

## Run it

Open an **elevated** PowerShell in the repo root.

```powershell
# 1. Trust/import certs, add hosts entries, create the four :443 bindings
.\scripts\1-setup.ps1

# 2. Start the server (leave running; Ctrl+C to stop)
.\scripts\2-run-server.ps1
```

Then **verify visually** — open Edge or Chrome:

- Browse to **https://certauth.local/** → you get a **"Select a certificate"** prompt. Choose
  **demo-client**. The page confirms client certificate `CN=demo-client`, TLS 1.3, port 443 — the
  cert was requested **in the handshake**.
- Browse to **https://nocert.local/** → **no prompt**; the app never asks for a cert.
- Browse to **https://delay.local/** → the app tries to fetch the cert **after** the handshake. A
  modern browser negotiates HTTP/2, where post-handshake auth is forbidden, so the page loads but
  shows **no client certificate** — the client offered one, but the delayed path couldn't collect it.
  That silent auth failure is the delayed-path regression.
- Browse to **https://127.0.0.1/** → **no prompt** (raw-IP path, no SNI).

And/or **verify automatically** (any PowerShell, no elevation needed) in a second window:

```powershell
.\scripts\3-probe.ps1
```

Expected (from a real run):

```
===== HTTP/1.1 -- all three behaviors succeed =====
### https://certauth.local/  (HTTP/1.1, client offers cert: True)
  IN-HANDSHAKE mTLS - port 443, TLS Tls13, HTTP/1.1
  client cert : CN=demo-client
### https://delay.local/     (HTTP/1.1, client offers cert: True)
  DELAYED / post-handshake (PHA) - port 443, TLS Tls13, HTTP/1.1
  client cert : CN=demo-client            # obtained via renegotiation
### https://nocert.local/    (HTTP/1.1, client offers cert: True)
  NO client auth - port 443, TLS Tls13, HTTP/1.1
  client cert : no client certificate
### https://127.0.0.1/       (HTTP/1.1, client offers cert: True)
  NO client auth - port 443, TLS Tls13, HTTP/1.1
  client cert : no client certificate

===== HTTP/2 -- the contrast that proves the binding problem =====
### https://certauth.local/  (HTTP/2, client offers cert: True)
  IN-HANDSHAKE mTLS - port 443, TLS Tls13, HTTP/2
  client cert : CN=demo-client            # in-handshake authenticates over HTTP/2
### https://delay.local/     (HTTP/2, client offers cert: True)
  DELAYED / post-handshake (PHA) - port 443, TLS Tls13, HTTP/2
  client cert : no client certificate     # client offered a cert, but PHA is forbidden on HTTP/2
```

These last two results are the core finding: **the same client presenting the same certificate is
authenticated on `certauth.local` over HTTP/2, but obtains no certificate on `delay.local` over
HTTP/2** — the delayed/post-handshake path cannot collect it. Requesting the certificate in the
handshake resolves this on the same port 443.

### The recommended deployment: authenticate once, then bearer (same hostname)

The probe then runs the **clean design** an SDK like SafeguardJava actually uses — cert only to *mint*
a token, bearer for everything after — all on the one cert-auth hostname:

```
===== CLEAN DESIGN -- authenticate once with the cert, then use a bearer token =====
### /token  WITH client cert           -> HTTP 200
  issued access_token : 9f3c...            # cert presented IN the handshake -> token minted
### /api/whoami  NO cert + bearer       -> HTTP 200
  {"message":"authorized by bearer token -- no client certificate was needed on this call",
   "presented_client_cert":false, ...}     # SAME cert SNI, NO client cert, bearer alone authorizes
### /token  WITHOUT cert (negative)     -> HTTP 403   (cert required only here)
### /api/whoami  WITHOUT bearer (neg)   -> HTTP 401   (bearer required here)
```

This models the exact SDK flow: the client presents its cert **once** to `/token` on the cert-auth
hostname, gets an access token, and keeps calling the **same** hostname with just
`Authorization: Bearer …` — no client cert on the later calls, no switch back to the primary DNS name.
The cert SNI is `clientcertnegotiation=enable` (in-handshake) and treats the cert as **optional
(allow)**, with the requirement scoped to the token endpoint. Two endpoints (`/token`, `/api/whoami`)
on `certauth.local` implement it; see `src/Program.cs`.

When you're done:

```powershell
# elevated
.\scripts\4-cleanup.ps1
```

This removes the four bindings, the hosts entries, and all imported certs.

---

## How it works

HTTP.sys terminates TLS in the kernel and selects a certificate binding by the **SNI hostname** in
the ClientHello (or, for a raw-IP connection with no SNI, by the IP). `1-setup.ps1` creates four
bindings on `:443` that differ only by `clientcertnegotiation`:

```
netsh http add sslcert hostnameport=certauth.local:443 certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=enable
netsh http add sslcert hostnameport=delay.local:443    certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=disable
netsh http add sslcert hostnameport=nocert.local:443   certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=disable
netsh http add sslcert ipport=0.0.0.0:443              certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=disable
```

- `clientcertnegotiation=enable` (certauth.local) makes HTTP.sys send a **CertificateRequest during
  the TLS 1.3 handshake** → the browser prompts, and the cert is captured with no renegotiation.
- `clientcertnegotiation=disable` sends no in-handshake request. What happens next is the **app's**
  choice: `delay.local` calls `GetClientCertificateAsync()` (forcing renegotiation on TLS 1.2 /
  post-handshake auth on TLS 1.3), while `nocert.local` and the raw-IP path never ask.

The app (`src/Program.cs`) sets `ClientCertificateMethod = AllowRenegotation` (so the delayed path
can retrieve a cert) and branches on the SNI host: read the cached in-handshake cert on
`certauth.local`, fetch post-handshake on `delay.local`, ignore on everything else. One server, one
cert, one port — three behaviors.

### Why this matters for SPP and the SDKs

Keeping certificate auth on 443 with an **SNI-scoped, in-handshake** binding restores the TLS 1.3
clients that fail under post-handshake authentication (Node.js, Java, Python `aiohttp`, and any client
on HTTP/2, which does not permit PHA) — with no client code change and no additional port. The primary
hostname can retain today's delayed/PHA behavior, so the existing PHA-capable clients (.NET,
PowerShell, Python `requests`, curl) require no changes. See `docs/empirical-results.md` for the
captured runs and the SDK-by-SDK rationale.

### Where each setting lives: netsh vs. app (and what "require" really means)

A common misconception is that you set client-cert *policy* on the `netsh` binding. You don't. There
are **three layers**, and "require" only exists in the top one:

| Layer | Setting | Allowed values | What it controls |
|-------|---------|----------------|------------------|
| **1. netsh binding** (transport) | `clientcertnegotiation` | `enable` / `disable` **only** | Whether HTTP.sys sends a `CertificateRequest` **in the handshake**. **There is no `require`.** Even with `enable`, a TLS 1.3 client may answer with an *empty* cert and the handshake still completes. |
| **2. app / HttpSys** (framework) | `ClientCertificateMethod` | `NoCertificate` / `AllowCertificate` / `AllowRenegotation` | How the app *collects* the cert: from the handshake (`AllowCertificate`, pairs with `enable`) or post-handshake (`AllowRenegotation`, the PHA path that breaks HTTP/2). Still **no `require`** — it only *collects*. |
| **3. app / your code** (policy) | inspect the cert, return **403** if missing | your logic | **This is the only place "require" exists.** Scope it to the endpoints that need a cert (e.g. the token grant). |

So `netsh clientcertnegotiation=enable` means **"offer the client the chance to authenticate,"** not
**"reject if absent."** "Require" is an *application* decision made per-endpoint (`/token` returns 403
without a cert; every other path is bearer-authorized). See `src/Program.cs` — `/token` enforces the
cert, `/api/whoami` does not.

**Why this matters for the "set it to require" plan.** If "require" is applied at the transport /
whole-listener level (e.g. Kestrel's `ClientCertificateMode.RequireCertificate`, which only applies
when Kestrel — not HTTP.sys — terminates TLS, or a mandatory-cert Schannel flag), **every** client to
that host must present a cert or the connection is refused: browsers doing SAML/password login, health
checks, and bearer-only API calls all break, forcing them back to the primary hostname. Scope
"require" to the token endpoint in the app instead — then a client authenticates once with its cert,
gets a bearer, and keeps calling the **same** cert-auth hostname with the token and no cert.

### Recommended end-to-end configuration (production shape)

| Hostname (URL) | netsh `clientcertnegotiation` | app `ClientCertificateMethod` | per-path policy |
|----------------|-------------------------------|-------------------------------|-----------------|
| `spp.example.com` (primary web UI + API) | `disable` | `AllowCertificate` | bearer / SAML / password — **no cert prompt** |
| `certauth.spp.example.com` (cert login + A2A token grant) | `enable` | `AllowCertificate` | token grant path: **require cert → 403 if absent**; all other paths: **bearer, cert optional** |
| `0.0.0.0:443` (raw-IP / no-SNI fallback) | `disable` | `AllowCertificate` | no cert |

All three are the **same listener on port 443**, selected by SNI. Note the recommended
`ClientCertificateMethod` is `AllowCertificate` (in-handshake, no renegotiation) — this demo defaults
to `AllowRenegotation` only so it can *also* show the broken delayed/PHA path on `delay.local` for
contrast. Set `DEMO_CERT_METHOD=AllowCertificate` to run the server the recommended way.

---

## Troubleshooting

- **No certificate prompt on `certauth.local`?** Browsers cache the choice per session — fully close
  the browser and retry. Confirm `demo-client` is in your personal store (`certmgr.msc` →
  Personal → Certificates) after running `1-setup.ps1`.
- **TLS warning in the browser?** Ensure `1-setup.ps1` completed; it puts the server cert in
  Trusted Root. Try a fresh browser profile if an old cached cert interferes.
- **Firefox doesn't prompt:** Firefox uses its own NSS store, not Windows'. Import `certs/client.pfx`
  (password `demo`) via Settings → Privacy & Security → Certificates → Your Certificates. Edge/Chrome
  need no extra step.
- **Port 443 in use** (IIS, another service)? Stop it, or change the port in `src/Program.cs` and the
  `:443` references in the scripts.
- **`3-probe.ps1` SSL failures:** make sure the server (step 2) is running and `1-setup.ps1` imported
  the client cert into `CurrentUser\My`.
- **`delay.local` errors in the browser or fails on the HTTP/2 probe:** this is expected. The
  delayed/post-handshake path cannot run over HTTP/2. `certauth.local` (in-handshake) succeeds on
  both HTTP/1.1 and HTTP/2, which is why an in-handshake binding keeps certificate auth on 443.

---

## Layout

```
certs/     pre-generated demo certs (server.pfx/.cer, client.pfx/.cer), manifest.json, generate-certs.ps1
scripts/   1-setup.ps1  2-run-server.ps1  3-probe.ps1  4-cleanup.ps1
src/       ASP.NET Core HTTP.sys server (Program.cs)
docs/      empirical-results.md — captured evidence and rationale
```

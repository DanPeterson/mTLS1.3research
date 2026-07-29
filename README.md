# mTLS 1.3 on port 443 — empirical proof

**Claim under test:** *"TLS 1.3 client-certificate (mutual TLS) authentication requires its own
port; it can't share 443 with everything else."*

**Result:** False. This repo is a self-contained, runnable proof that on **one** port (443), on the
**exact production stack SPP uses** (ASP.NET Core on **HTTP.sys**), TLS 1.3 in-handshake mutual TLS
coexists with ordinary non-cert traffic — differentiated purely by the **SNI hostname**, via three
`netsh http add sslcert` bindings that differ only by one flag.

Run it yourself in ~2 minutes and watch a browser get prompted for a client certificate on one
hostname and **not** on another — same port, same server, same process.

---

## What you'll see

Three client-cert behaviors, all on port 443, selected purely by the SNI hostname:

| You browse to | netsh binding | App behavior | Models | Browser |
|---------------|---------------|--------------|--------|---------|
| `https://certauth.local/` | `clientcertnegotiation=enable` | reads cached cert | **in-handshake mTLS** (the fix) | **Prompts**; page shows `CN=demo-client` |
| `https://delay.local/` | `clientcertnegotiation=disable` | `GetClientCertificateAsync()` | **delayed / PHA** (SPP's current default) | prompts on HTTP/1.1; over HTTP/2 gets **no cert** (auth fails) |
| `https://nocert.local/` | `clientcertnegotiation=disable` | never reads cert | **no client auth** (opt-out) | **No prompt** |
| `https://127.0.0.1/` | `clientcertnegotiation=disable` (IP) | never reads cert | no client auth (raw IP) | **No prompt** |

`delay.local` and `nocert.local` carry the **same** netsh flag — the only difference is whether the
app asks for the cert. That's the point: in-handshake vs delayed vs none is one SNI-scoped binding
plus one app decision. No second port anywhere.

**The HTTP/2 contrast (`3-probe.ps1`) is the money shot:** `certauth.local` authenticates the client
cert over **both** HTTP/1.1 and HTTP/2, while `delay.local` gets **no cert over HTTP/2** — because
HTTP/2 forbids the post-handshake authentication the delayed path depends on. The same client offering
the same cert authenticates on the in-handshake binding but not the delayed one. That gap is the real
reason behind the 7443 proposal, and the in-handshake binding closes it on the same port.

All hosts resolve to the same `0.0.0.0:443` listener in one process, using one server certificate.
Only the SNI/IP-selected binding differs. That is the entire point: **no second port is needed.**

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

The last two lines are the whole argument: **the same client offering the same certificate is
authenticated on `certauth.local` over HTTP/2, but gets no cert on `delay.local` over HTTP/2** — the
delayed/post-handshake path can't collect it. Move the request to the in-handshake binding and it
works, on the same port 443.

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

Keeping cert auth on 443 with an **SNI-scoped, in-handshake** binding fixes the TLS 1.3 clients that
break under post-handshake auth (Node.js, Java, Python `aiohttp`, and anything on HTTP/2, which
forbids PHA) **without a client code change and without a second port**. The default hostname can
keep today's delayed/PHA behavior so the existing PHA-capable fleet (.NET, PowerShell, Python
`requests`, curl) is zero-touch. See `docs/empirical-results.md` for the captured runs and the
SDK-by-SDK rationale.

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
- **`delay.local` errors in the browser or fails on the HTTP/2 probe:** that's **expected and is the
  point** — the delayed/post-handshake path can't run over HTTP/2. `certauth.local` (in-handshake)
  succeeds on both HTTP/1.1 and HTTP/2, which is the whole argument for keeping cert auth on 443 with
  an in-handshake binding.

---

## Layout

```
certs/     pre-generated demo certs (server.pfx/.cer, client.pfx/.cer), manifest.json, generate-certs.ps1
scripts/   1-setup.ps1  2-run-server.ps1  3-probe.ps1  4-cleanup.ps1
src/       ASP.NET Core HTTP.sys server (Program.cs)
docs/      empirical-results.md — captured evidence and rationale
```

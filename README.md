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

| You browse to | Binding (`netsh clientcertnegotiation`) | Browser behavior |
|---------------|------------------------------------------|------------------|
| `https://certauth.local/` | **enable** (in-handshake CertificateRequest) | **Prompts** you to choose a client cert; page shows `CN=demo-client` |
| `https://delay.local/`    | disable | **No prompt**; ordinary page |
| `https://127.0.0.1/`      | disable (IP fallback) | **No prompt**; ordinary page |

All three resolve to the same `0.0.0.0:443` listener in one process, using one server certificate.
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
# 1. Trust/import certs, add hosts entries, create the three :443 bindings
.\scripts\1-setup.ps1

# 2. Start the server (leave running; Ctrl+C to stop)
.\scripts\2-run-server.ps1
```

Then **verify visually** — open Edge or Chrome:

- Browse to **https://certauth.local/** → you get a **"Select a certificate"** prompt. Choose
  **demo-client**. The page confirms `client certificate: CN=demo-client`, TLS 1.3, port 443.
- Browse to **https://delay.local/** → **no prompt**; the page says it's the primary endpoint.
- Browse to **https://127.0.0.1/** → **no prompt** (raw-IP path, no SNI).

And/or **verify automatically** (any PowerShell, no elevation needed) in a second window:

```powershell
.\scripts\3-probe.ps1
```

Expected:

```
### https://certauth.local/   (client offers cert: True)
  CERT-AUTH endpoint - served on port 443, TLS Tls13
  client cert : client certificate: CN=demo-client
### https://delay.local/      (client offers cert: True)
  PRIMARY endpoint - served on port 443, TLS Tls13
  client cert : client certificate not requested on this host
### https://127.0.0.1/        (client offers cert: True)
  PRIMARY endpoint - served on port 443, TLS Tls13
  client cert : client certificate not requested on this host
### https://certauth.local/   (client offers cert: False)
  CERT-AUTH endpoint - served on port 443, TLS Tls13
  client cert : no client certificate presented
```

When you're done:

```powershell
# elevated
.\scripts\4-cleanup.ps1
```

This removes the three bindings, the hosts entries, and all three imported certs.

---

## How it works

HTTP.sys terminates TLS in the kernel and selects a certificate binding by the **SNI hostname** in
the ClientHello (or, for a raw-IP connection with no SNI, by the IP). `1-setup.ps1` creates three
bindings on `:443` that are **identical except for `clientcertnegotiation`**:

```
netsh http add sslcert hostnameport=certauth.local:443 certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=enable
netsh http add sslcert hostnameport=delay.local:443    certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=disable
netsh http add sslcert ipport=0.0.0.0:443              certhash=<server> appid=<guid> certstorename=MY clientcertnegotiation=disable
```

- `clientcertnegotiation=enable` makes HTTP.sys send a **CertificateRequest during the TLS 1.3
  handshake** → the browser prompts, and the cert is captured with no renegotiation.
- `clientcertnegotiation=disable` sends no in-handshake request → no prompt.

The app (`src/Program.cs`) is a constant: `ClientCertificateMethod = AllowCertificate` (read the
handshake-captured cert, **never renegotiate**), and it only reads the client cert on
`certauth.local` so the primary host is completely undisturbed.

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

---

## Layout

```
certs/     pre-generated demo certs (server.pfx/.cer, client.pfx/.cer), manifest.json, generate-certs.ps1
scripts/   1-setup.ps1  2-run-server.ps1  3-probe.ps1  4-cleanup.ps1
src/       ASP.NET Core HTTP.sys server (Program.cs)
docs/      empirical-results.md — captured evidence and rationale
```

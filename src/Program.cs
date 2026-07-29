using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.HttpSys;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

// mTLS-on-443 research demo -- the production SPP stack: ASP.NET Core on HTTP.sys.
//
// One process, one server certificate, one listener on 0.0.0.0:443. HTTP.sys routes each TLS
// connection to a netsh sslcert binding chosen by the SNI hostname (or the IP for raw-IP
// connections). The bindings created by scripts/1-setup.ps1 select THREE different client-cert
// behaviors -- all on the same port -- and the app reflects what each one negotiated:
//
//   certauth.local  netsh clientcertnegotiation=ENABLE   app reads Connection.ClientCertificate
//                   -> cert requested IN the TLS handshake, captured with NO renegotiation.
//                      This is the FIX: works for every client, including HTTP/2 and TLS 1.3
//                      clients that cannot do post-handshake auth.
//
//   delay.local     netsh clientcertnegotiation=DISABLE  app calls GetClientCertificateAsync()
//                   -> no in-handshake request; the cert is fetched AFTER the handshake via
//                      renegotiation (TLS 1.2) / post-handshake authentication (TLS 1.3).
//                      This models SPP's CURRENT default. It works for PHA-capable HTTP/1.1
//                      clients but FAILS over HTTP/2 (which forbids PHA) and for TLS 1.3 clients
//                      that don't implement PHA -- the exact regression behind the 7443 decision.
//
//   nocert.local    netsh clientcertnegotiation=DISABLE  app never reads the cert
//   (and raw IP)    -> no client authentication at all (opt-out / "PHA off").
//
// delay.local and nocert.local carry the SAME netsh flag; the only difference is whether the app
// asks for the cert. That is the teaching point: in-handshake vs delayed vs none is a combination
// of the SNI-scoped binding and one app decision -- no second port anywhere.

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseHttpSys(options =>
{
    options.UrlPrefixes.Add("https://+:443/");
    // AllowRenegotation permits the delayed/post-handshake retrieval that delay.local demonstrates.
    // certauth.local still gets its cert IN the handshake (enable binding), so no renegotiation
    // occurs there; nocert.local never asks. Override with DEMO_CERT_METHOD if you want to compare.
    options.ClientCertificateMethod = Enum.TryParse<ClientCertificateMethod>(
        Environment.GetEnvironmentVariable("DEMO_CERT_METHOD"), true, out var m)
        ? m : ClientCertificateMethod.AllowRenegotation;
});

var app = builder.Build();

app.Run(async context =>
{
    var conn = context.Connection;
    var tls = context.Features.Get<ITlsHandshakeFeature>();
    string host = context.Request.Host.Host;
    string httpProtocol = context.Request.Protocol; // HTTP/1.1 vs HTTP/2 -- matters for the delayed path

    string mode, modeDetail;
    X509Certificate2? clientCert = null;
    string? error = null;

    if (string.Equals(host, "certauth.local", StringComparison.OrdinalIgnoreCase))
    {
        // IN-HANDSHAKE: the cert was requested during the TLS handshake (enable binding) and is
        // already captured. Reading the property returns it WITHOUT any renegotiation.
        mode = "IN-HANDSHAKE mTLS";
        modeDetail = "netsh clientcertnegotiation=<b>enable</b> &rarr; cert requested during the TLS handshake, read from cache (no renegotiation). Works on HTTP/1.1 AND HTTP/2.";
        clientCert = conn.ClientCertificate;
    }
    else if (string.Equals(host, "delay.local", StringComparison.OrdinalIgnoreCase))
    {
        // DELAYED / PHA: no in-handshake request. Fetch the cert AFTER the handshake, which forces
        // renegotiation (TLS 1.2) or post-handshake authentication (TLS 1.3). This is the path that
        // breaks over HTTP/2 (PHA forbidden) and for TLS 1.3 clients without PHA support.
        mode = "DELAYED / post-handshake (PHA)";
        modeDetail = "netsh clientcertnegotiation=<b>disable</b> &rarr; cert fetched AFTER the handshake via <code>GetClientCertificateAsync()</code> (renegotiation on 1.2, PHA on 1.3). <b>Fails over HTTP/2.</b>";
        try
        {
            clientCert = await conn.GetClientCertificateAsync(context.RequestAborted);
        }
        catch (Exception ex)
        {
            // Over HTTP/2 the post-handshake request cannot be issued -> this is the regression.
            error = ex.GetType().Name + ": " + ex.Message;
        }
    }
    else
    {
        // OPT-OUT: same disable binding as delay.local, but the app never asks for a cert.
        mode = "NO client auth";
        modeDetail = "netsh clientcertnegotiation=<b>disable</b> &rarr; app never reads the certificate. No client authentication (opt-out / \"PHA off\").";
    }

    string tlsVersion = tls?.Protocol.ToString() ?? "(unknown)";
    string certLine =
        error is not null
            ? $"<span class='no'>could not obtain client certificate &mdash; {WebUtility.HtmlEncode(error)}</span>"
            : clientCert is null
                ? "<span class='muted'>no client certificate</span>"
                : $"<span class='yes'>{WebUtility.HtmlEncode(clientCert.Subject)}</span>";
    string banner =
        error is not null ? "#c62828"
        : clientCert is not null ? "#2e7d32"
        : "#1565c0";

    string html = $$"""
<!doctype html>
<html><head><meta charset="utf-8"><title>mTLS 1.3 on 443 -- {{host}}</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#222}
 .banner{background:{{banner}};color:#fff;padding:1rem 1.25rem;border-radius:8px;font-size:1.15rem;font-weight:600}
 table{border-collapse:collapse;margin:1.25rem 0;width:100%}
 td{border:1px solid #ddd;padding:.5rem .75rem;vertical-align:top}
 td.k{background:#f6f6f6;font-weight:600;width:190px}
 .yes{color:#2e7d32;font-weight:700}.no{color:#c62828;font-weight:700}.muted{color:#777}
 code{background:#f2f2f2;padding:.1rem .3rem;border-radius:4px}
 nav a{margin-right:1rem}
</style></head><body>
<div class="banner">{{mode}} &mdash; port 443, TLS {{tlsVersion}}, {{httpProtocol}}</div>
<table>
 <tr><td class="k">Host (SNI)</td><td><code>{{WebUtility.HtmlEncode(host)}}</code></td></tr>
 <tr><td class="k">Local endpoint</td><td><code>{{conn.LocalIpAddress}}:{{conn.LocalPort}}</code></td></tr>
 <tr><td class="k">TLS version</td><td><code>{{tlsVersion}}</code></td></tr>
 <tr><td class="k">HTTP version</td><td><code>{{httpProtocol}}</code></td></tr>
 <tr><td class="k">Negotiation</td><td>{{modeDetail}}</td></tr>
 <tr><td class="k">Client cert</td><td>{{certLine}}</td></tr>
</table>
<p>All three hosts below resolve to the same listener on <b>0.0.0.0:443</b> in the same process,
with the same server certificate. Only the SNI-selected <code>netsh</code> binding and one app
decision differ.</p>
<nav>
 <a href="https://certauth.local/">certauth.local (in-handshake)</a>
 <a href="https://delay.local/">delay.local (delayed / PHA)</a>
 <a href="https://nocert.local/">nocert.local (no auth)</a>
</nav>
<p class="muted"><b>certauth.local</b> prompts for a certificate during the initial handshake and
works in every browser. <b>delay.local</b> tries to fetch the cert AFTER the handshake, so a modern
browser (HTTP/2) may fail or error here &mdash; that is the regression the in-handshake binding
fixes. <b>nocert.local</b> never asks.</p>
</body></html>
""";

    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.WriteAsync(html);
});

app.Run();

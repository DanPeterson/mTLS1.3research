using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.HttpSys;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;

// mTLS-on-443 research demo -- the production SPP stack: ASP.NET Core on HTTP.sys.
//
// HTTP.sys routes each TLS connection to a netsh sslcert binding chosen by the SNI hostname
// (or the IP for raw-IP connections). The bindings created by scripts/1-setup.ps1 differ ONLY
// by the clientcertnegotiation flag:
//
//   hostnameport=certauth.local:443  clientcertnegotiation=ENABLE   -> in-handshake CertificateRequest
//   hostnameport=delay.local:443     clientcertnegotiation=DISABLE  -> no in-handshake request
//   ipport=0.0.0.0:443               clientcertnegotiation=DISABLE  -> IP / wildcard fallback
//
// The app is a constant. It only READS the client certificate on the cert-auth host, so the
// primary host performs NO post-handshake renegotiation and a browser is never prompted there.
// On certauth.local the certificate was already captured during the TLS handshake (ENABLE binding),
// so AllowCertificate returns it without any renegotiation.

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseHttpSys(options =>
{
    options.UrlPrefixes.Add("https://+:443/");
    options.ClientCertificateMethod = ClientCertificateMethod.AllowCertificate; // no renegotiation
});

var app = builder.Build();

app.Run(async context =>
{
    var conn = context.Connection;
    var tls = context.Features.Get<ITlsHandshakeFeature>();
    string host = context.Request.Host.Host;
    bool certAuthHost = string.Equals(host, "certauth.local", StringComparison.OrdinalIgnoreCase);

    // Only touch the client cert on the cert-auth host -> primary host never renegotiates.
    X509Certificate2? clientCert = certAuthHost ? conn.ClientCertificate : null;

    string tlsVersion = tls?.Protocol.ToString() ?? "(unknown)";
    string role = certAuthHost ? "CERT-AUTH endpoint" : "PRIMARY endpoint";
    string binding = certAuthHost
        ? "netsh clientcertnegotiation=<b>enable</b> (in-handshake CertificateRequest)"
        : "netsh clientcertnegotiation=<b>disable</b> (no in-handshake request)";
    string certLine = certAuthHost
        ? (clientCert is null
            ? "<span class='no'>no client certificate presented</span>"
            : $"<span class='yes'>client certificate: {WebUtility.HtmlEncode(clientCert.Subject)}</span>")
        : "<span class='muted'>client certificate not requested on this host</span>";
    string banner = certAuthHost
        ? (clientCert is null ? "#b58900" : "#2e7d32")
        : "#1565c0";

    string html = $$"""
<!doctype html>
<html><head><meta charset="utf-8"><title>mTLS 1.3 on 443 -- {{host}}</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;color:#222}
 .banner{background:{{banner}};color:#fff;padding:1rem 1.25rem;border-radius:8px;font-size:1.15rem;font-weight:600}
 table{border-collapse:collapse;margin:1.25rem 0;width:100%}
 td{border:1px solid #ddd;padding:.5rem .75rem;vertical-align:top}
 td.k{background:#f6f6f6;font-weight:600;width:190px}
 .yes{color:#2e7d32;font-weight:700}.no{color:#b58900;font-weight:700}.muted{color:#777}
 code{background:#f2f2f2;padding:.1rem .3rem;border-radius:4px}
 nav a{margin-right:1rem}
</style></head><body>
<div class="banner">{{role}} &mdash; served on port 443, TLS {{tlsVersion}}</div>
<table>
 <tr><td class="k">Host (SNI)</td><td><code>{{WebUtility.HtmlEncode(host)}}</code></td></tr>
 <tr><td class="k">Local endpoint</td><td><code>{{conn.LocalIpAddress}}:{{conn.LocalPort}}</code></td></tr>
 <tr><td class="k">TLS version</td><td><code>{{tlsVersion}}</code></td></tr>
 <tr><td class="k">Binding policy</td><td>{{binding}}</td></tr>
 <tr><td class="k">Client cert</td><td>{{certLine}}</td></tr>
</table>
<p>All three hosts below resolve to the same listener on <b>0.0.0.0:443</b> in the same process,
with the same server certificate. Only the SNI/IP-selected <code>netsh</code> binding differs.</p>
<nav>
 <a href="https://certauth.local/">certauth.local (mTLS)</a>
 <a href="https://delay.local/">delay.local (primary)</a>
 <a href="https://127.0.0.1/">127.0.0.1 (IP)</a>
</nav>
<p class="muted">Browsing to <b>certauth.local</b> should prompt you to choose a client certificate
(the in-handshake TLS 1.3 request). <b>delay.local</b> and <b>127.0.0.1</b> should NOT prompt.
That contrast, on one port, is the whole point.</p>
</body></html>
""";

    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.WriteAsync(html);
});

app.Run();

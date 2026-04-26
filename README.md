# checker-ns-restrictions

Authoritative nameserver security restrictions checker for [happyDomain](https://www.happydomain.org/).

For each nameserver of an `abstract.Origin` or `abstract.NSOnlyOrigin`
service, this checker verifies common security misconfigurations:

| Check                          | Severity on failure |
|--------------------------------|---------------------|
| AXFR zone transfer refused     | CRITICAL            |
| IXFR zone transfer refused     | WARNING             |
| Recursion not available (RA)   | WARNING             |
| ANY query handling (RFC 8482)  | WARNING             |
| Authoritative answer (AA bit)  | INFO                |

The checker resolves each NS host, then runs the five DNS probes against
every returned IPv4/IPv6 address. IPv6 targets are skipped gracefully if
the host has no IPv6 connectivity.

## Usage

### Standalone HTTP server

```bash
make
./checker-ns-restrictions -listen :8080
```

The server exposes the standard happyDomain external checker protocol
(`/health`, `/collect`, `/evaluate`, `/definition`).

### Docker

```bash
make docker
docker run -p 8080:8080 happydomain/checker-ns-restrictions
```

### happyDomain plugin

```bash
make plugin
# produces checker-ns-restrictions.so, loadable by happyDomain as a Go plugin
```

The plugin exposes a `NewCheckerPlugin` symbol returning the checker
definition and observation provider, which happyDomain registers in its
global registries at load time.

### Deployment

The `/collect` endpoint has no built-in authentication and will issue
DNS queries (including AXFR/IXFR/ANY zone-transfer attempts) to whatever
addresses the supplied NS hostnames resolve to. A caller that controls
the input domain can publish NS records pointing at arbitrary IPs,
including private/internal ranges (RFC 1918, loopback, link-local) or
unrelated third-party hosts, and use this checker as an SSRF / probing
relay against them. It is meant to run on a trusted network, reachable
only by the happyDomain instance that drives it. Restrict access via a
reverse proxy with authentication, a network ACL, or by binding the
listener to a private interface; do not expose it directly to the
public internet.

### Versioning

The binary, plugin, and Docker image embed a version string overridable
at build time:

```bash
make CHECKER_VERSION=1.2.3
make plugin CHECKER_VERSION=1.2.3
make docker CHECKER_VERSION=1.2.3
```

## License

This project does **not** depend on the happyDomain core repository: the
few host types it needs (`ServiceMessage`, `abstract.Origin`,
`abstract.NSOnlyOrigin`) are mirrored as minimal local copies of their
JSON wire shapes. It only depends on
[`checker-sdk-go`](https://git.happydns.org/checker-sdk-go) (Apache 2.0)
and [`miekg/dns`](https://github.com/miekg/dns) (BSD 3-Clause).

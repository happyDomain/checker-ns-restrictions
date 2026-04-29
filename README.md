# checker-ns-restrictions

Authoritative nameserver security restrictions checker for [happyDomain](https://www.happydomain.org/).

For each nameserver of an `abstract.Origin` or `abstract.NSOnlyOrigin`
service, this checker resolves each NS host then runs a set of DNS probes
against every returned IPv4/IPv6 address. IPv6 targets are skipped
gracefully if the host has no IPv6 connectivity. See [Rules](#rules) below
for the full list of checks performed.

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

## Rules

Each rule emits one `CheckState` per probed nameserver address, carrying a
stable `code` so downstream consumers can match on them deterministically.

| Rule                  | Description                                                                                       | Severity on failure |
|-----------------------|---------------------------------------------------------------------------------------------------|---------------------|
| `ns_resolution`       | Verifies that every NS host name declared in the delegation resolves to at least one IP address.  | CRITICAL            |
| `ns_axfr_refused`     | Verifies that AXFR zone transfers are refused by every authoritative nameserver.                  | CRITICAL            |
| `ns_ixfr_refused`     | Verifies that IXFR zone transfers are refused by every authoritative nameserver.                  | WARNING             |
| `ns_no_recursion`     | Verifies that authoritative nameservers do not advertise recursion (RA bit unset).                | WARNING             |
| `ns_any_handled`      | Verifies that ANY queries are handled per RFC 8482 (HINFO or minimal answer).                     | WARNING             |
| `ns_is_authoritative` | Verifies that nameservers answer authoritatively (AA bit set) for the zone.                      | INFO                |

## License

MIT (see `LICENSE`). Third-party attributions in `NOTICE`.

# DNS

[![CI](https://github.com/spider-gazelle/dns/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/dns/actions/workflows/ci.yml)

Non-blocking extendable DNS client for crystal lang.

With built in support for UDP, TLS, HTTPS and mDNS resolvers.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     dns:
       github: spider-gazelle/dns
   ```

2. Run `shards install`

## Usage

A simple query

```crystal
require "dns"

responses = DNS.query(
  "www.google.com",
  {
    DNS::RecordType::A,
    DNS::RecordType::AAAA,
  }
)

ips = responses.map(&.ip_address)

```

How to configure custom resolvers (secure from prying eyes)

```crystal
require "dns"
require "dns/resolver/https"

DNS.default_resolver = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

# or just for some routes
DNS.resolvers[/.+\.com\.au$/i] = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

# there is a built in resolver to use mDNS for *.local routes

# if you'd prefer to use the system resolver for A and AAAA records
DNS.default_resolver = DNS::Resolver::System.new(
  # uses the fallback resolver for other DNS records
  fallback: DNS::Resolver::UDP.new
)

# for the TLS resolver you need to specify a domain name for the returned TLS certificate
DNS.default_resolver = DNS::Resolver::TLS.new({
  "8.8.8.8" => "dns.google",
})

# or maybe you don't want to use the system defined DNS servers
DNS.default_resolver = DNS::Resolver::UDP.new(["1.1.1.1", "8.8.8.8"])

# it's also possible to create your own resolvers implementing the abstract method in `DNS::Resolver`

```

By default, the library will attempt to obtain the DNS servers configured on your host. That is using:

* `/etc/resolv.conf` on linux / nix* systems
* [Win32 API calls](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_dns_server_address_xp) on Windows
* SystemConfiguration framework on MacOS

NOTE:: currently it does not check if DNS over HTTPS is configured on either Mac or Windows (future work)

If DNS discovery is unsuccessful it falls back to using `["1.1.1.1", "8.8.8.8"]`.

```crystal
# to customise the fallback servers
DNS::Servers.fallback = ["192.168.0.1"]
```

## Resolver behaviour

The UDP resolver is modelled on the behaviour of unix `getaddrinfo`:

* queries are retransmitted with an exponential backoff and failed over across
  the configured nameservers, rather than failing on a single dropped packet
* a persistently unresponsive nameserver is demoted to the end of the list so
  later queries prefer healthy servers
* `resolv.conf` options are honoured: `timeout:` (default `2s`, clamped `1..30`),
  `attempts:` (default `3`, clamped `1..5`) and `ndots:` (default `1`, clamped
  `0..15`). Set the global base timeout with `DNS.timeout`. An explicit
  `timeout:` in `resolv.conf` or a resolver's server configuration takes precedence.
* UDP advertises a 1232-byte EDNS0 payload. When the query has no required EDNS
  options or negotiated cookie, the resolver also tries without EDNS if the
  server rejects it or stays silent through half the attempt. Truncated (`TC`)
  replies are refetched over TCP within the same deadline.

```crystal
# tune the base (initial) per-try timeout; backoff doubles it each attempt
DNS.timeout = 1.second
```

### Shared UDP source port

All UDP queries are sent from a single, long-lived source port per address
family (a process-wide `DNS::Resolver::UDP::SharedSocket`) rather than opening a
fresh socket per query. A background fiber demultiplexes responses back to each
waiting query by transaction id.

Reusing one source port trades some of the source-port entropy recommended by
[RFC 5452](https://datatracker.ietf.org/doc/html/rfc5452) for connection reuse,
so every response is strictly validated before it is accepted: the transaction
id (a CSPRNG value) must be outstanding, the `QR` bit must be set, the source
address must match the queried server, and the echoed question must match the
request. An EDNS rejection without an echoed question can trigger a legacy
retry. This is appropriate for a stub resolver talking to a trusted recursive
resolver. If you operate over an untrusted path, prefer the TLS or HTTPS
resolvers.

UDP negotiates DNS Cookies per upstream and local address. A valid
`BADCOOKIE` response triggers a retry with the replacement cookie, followed
by TCP if the server challenges the retry. Set `resolver.dns_cookies = false`
to disable negotiation.

### EDNS options and service bindings

UDP, TCP fallback, DNS-over-TLS, and DNS-over-HTTPS can send options configured
on the resolver's `edns_options` property. Low-level packet callers can pass
a `DNS::Packet::EDNS` to `Question.build_query` and read reply options through
`packet.edns`. Extended DNS Errors are available through
`packet.extended_errors` or `DNS::Packet::Error#extended_errors` when a
lookup raises.

`DNS::Resource::SVCB` and `DNS::Resource::HTTPS` expose typed ALPN, port, and
address hints. Pass the parameter keys your application can honor to
`compatible?(supported_keys)` before using a service binding.

### DNSSEC-aware queries

Use `DNS.query_packet` to inspect the upstream's DNSSEC flags and the records
in its answer and authority sections. This lookup treats the name as fully
qualified and bypasses the library's hosts file and cache.

```crystal
resolver = DNS::Resolver::TLS.new({"8.8.8.8" => "dns.google"})
options = DNS::DNSSEC::Options.new(request_ad: true)
packet = DNS.query_packet("example.com.", DNS::RecordType::A, resolver: resolver, dnssec: options)
packet.raise_on_error!
puts packet.authenticated_data?
```

`request_ad: true` asks the upstream to report the outcome of validation using
the Authenticated Data (AD) bit. The configured recursive resolver performs
signature validation. Rely on AD only with a trusted validating upstream over
an authenticated connection such as certificate-verified TLS or HTTPS.
[RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html#section-4.9) · [RFC 6840](https://www.rfc-editor.org/rfc/rfc6840.html#section-5.7)

`dnssec_ok: true` sets the EDNS DO bit to request DNSSEC records. These lookups
keep EDNS on UDP retries and TCP fallback. RRSIG, DNSKEY, DS, and authenticated
denial records are available through their resource record type and raw
`resource_data`. `checking_disabled: true` sets CD for diagnostics when the
application needs the data the upstream would otherwise withhold.

### Local DNSSEC validation

`DNS::DNSSEC::Validator` verifies DNSSEC locally. It uses a recursive resolver
to fetch the answer, DS records, and DNSKEY RRsets. It verifies signatures
from a configured trust anchor and checks NSEC or NSEC3 proofs for negative
answers and wildcard expansion. [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html#section-5) · [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155.html#section-8)

```crystal
resolver = DNS::Resolver::TLS.new({"8.8.8.8" => "dns.google"})
validator = DNS::DNSSEC::Validator.new(resolver)
result = validator.query("example.com.", DNS::RecordType::A)

if result.secure?
  puts result.answers.select(&.record_type.a?).map(&.ip_address)
else
  puts "#{result.status} - #{result.reason}"
end
```

Only `Secure` results contain authenticated answer records. A `Secure` result
with response code 3 authenticates NXDOMAIN. An authenticated NODATA result
has response code 0 and no records of the requested type. `Insecure` indicates
an authenticated unsigned delegation, or a delegation whose authenticated DS
records use only unsupported algorithms or digests. `Bogus` indicates failed
verification, and `Indeterminate` means validation could not be completed.

The validator uses the bundled IANA root DS snapshot by default. Supply
`trust_anchors:` with an array of `DNS::DNSSEC::TrustAnchor` entries to update
the snapshot or validate a private zone. Supported signatures are RSA/SHA-256,
RSA/SHA-512, ECDSA P-256 and P-384, Ed25519, and Ed448. Supported DS digests
are SHA-256 and SHA-384. NSEC3 is bounded to SHA-1 and 150 iterations.
[IANA root trust anchors](https://www.iana.org/dnssec/files)

#### Require local DNSSEC validation for `DNS.query`

Install a validating default resolver at startup to require locally
authenticated answers from both forms of `DNS.query`.

```crystal
require "dns"

upstream = DNS::Resolver::TLS.new({"8.8.8.8" => "dns.google"})
DNS.default_resolver = DNS::Resolver::Validating.new(upstream)

answers = DNS.query("example.com.", [DNS::RecordType::A, DNS::RecordType::AAAA])
```

An `Insecure`, `Bogus`, or `Indeterminate` result raises
`DNS::DNSSEC::ValidationError` with the corresponding `status`.
Authenticated NXDOMAIN raises `DNS::Packet::NameError`, and authenticated
NODATA returns no records of the requested type.

Strict lookups use the configured upstream and its search domains. They
bypass the hosts file, shared cache, and resolver routes such as mDNS.
IP literals raise `ValidationError` because they have no DNSSEC proof.
Use `trust_anchors:` on `DNS::Resolver::Validating.new` for signed private zones.
`DNS.query_packet` remains available for inspecting raw upstream packets.

Other things to note:

* IPv6 is supported and handled transparently
* the cache keeps complete record sets and expires them using their shortest TTL, including any CNAMEs they depend on
* NXDOMAIN is cached by name and NODATA by name and query type, with expiration derived from the authority section's SOA
* additional records can satisfy later lookups while a cached direct answer takes precedence
* network results are cached by name and resolver. Entries inserted directly into `DNS.cache` by the application are shared.
* search candidates use any resolver route that matches their expanded name, including mDNS for `.local`
* `require "dns/ext/addrinfo"` uses this library for socket name lookups. Hostname-based DoH endpoints are bootstrapped with the system resolver.

Set `ipv4_interface` to a local IPv4 address or `ipv6_interface` to an interface
index when a multicast query needs a specific interface.

The specs use local fixtures and run without public DNS. Run the mDNS specs
with `crystal spec spec/mdns_resolver_spec.cr`. On Linux this includes a multicast
query over the loopback interface.

## Contributing

1. Fork it (<https://github.com/spider-gazelle/dns/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer

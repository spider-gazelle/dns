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
    DNS::RecordCode::A,
    DNS::RecordCode::AAAA,
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
  fallback: Resolver::UDP.new
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

Other things to note:

* IPv6 is supported and handled transparently
* a DNS cache is maintained and used based on TTL of responses
* DNS servers may return results of expected future queries, these results are cached
* force all DNS lookups to occur via this library: `require "dns/ext/addrinfo"`

## Contributing

1. Fork it (<https://github.com/spider-gazelle/dns/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer

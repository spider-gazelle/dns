# DNS

Non-blocking extendable DNS client for crystal lang.

With built in support for UDP, HTTPS and mDNS resolvers

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
  [
    DNS::RecordCode::A,
    DNS::RecordCode::AAAA,
  ]
)

ips = responses.map(&.ip_address)

```

Configure for HTTPS DNS (secure from prying eyes)

```crystal
require "dns"
require "dns/resolver/https"

DNS.default_resolver = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

# or just for some routes
DNS.resolvers[/.+\.com.au$/i] = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

# there is a built in resolver to use mDNS for *.local routes

```

## Contributing

1. Fork it (<https://github.com/your-github-user/dns/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer

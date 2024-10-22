# DNS

Non-blocking extensible DNS client for crystal lang

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     dns:
       github: spider-gazelle/dns
   ```

2. Run `shards install`

## Usage

```crystal
require "dns"

responses = DNS.query(
  "www.google.com",
  [
    DNS::RecordCode::A,
    DNS::RecordCode::AAAA,
  ]
)

ips = responses.map(&.to_ip_address)

```

## Contributing

1. Fork it (<https://github.com/your-github-user/dns/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Stephen von Takach](https://github.com/stakach) - creator and maintainer

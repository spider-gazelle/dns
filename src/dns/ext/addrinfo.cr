require "socket"

struct Socket::Addrinfo
  QUERY_INET   = [DNS::RecordType::A.value]
  QUERY_INET6  = [DNS::RecordType::AAAA.value]
  QUERY_UNSPEC = [DNS::RecordType::AAAA.value, DNS::RecordType::A.value]

  private def self.getaddrinfo(domain, service, family, type, protocol, timeout, &)
    if family.unix? || Socket::IPAddress.valid?(domain) || domain.includes?('/') || DNS.select_resolver(domain).is_a?(DNS::Resolver::System)
      # fallback to the original implementation in these cases
      domain = URI::Punycode.to_ascii domain
      Crystal::System::Addrinfo.getaddrinfo(domain, service, family, type, protocol, timeout) do |addrinfo|
        yield addrinfo
      end
      return
    end

    records = case family
              in .inet?
                QUERY_INET
              in .inet6?
                QUERY_INET6
              in .unspec?
                QUERY_UNSPEC
              in .unix?
                raise "unreachable"
              end

    DNS.query(domain, records) do |record|
      # we need to skip non-target records like cnames
      if record.type.in?(records)
        # this seems to be the way to get a valid addrinfo
        ip_address = record.ip_address.address
        Crystal::System::Addrinfo.getaddrinfo(ip_address, service, family, type, protocol, timeout) do |addrinfo|
          yield addrinfo
        end
      end
    end
  end
end

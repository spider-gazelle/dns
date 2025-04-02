require "socket"

struct Socket::Addrinfo
  QUERY_INET   = [DNS::Resource::A::RECORD_TYPE]
  QUERY_INET6  = [DNS::Resource::AAAA::RECORD_TYPE]
  QUERY_UNSPEC = [DNS::Resource::AAAA::RECORD_TYPE, DNS::Resource::A::RECORD_TYPE]

  private def self.getaddrinfo(domain, service, family, type, protocol, timeout, &)
    # fallback to the original implementation in these cases
    if family.unix? || Socket::IPAddress.valid?(domain) || domain.includes?('/') || DNS.select_resolver(domain).is_a?(DNS::Resolver::System)
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
                raise NotImplementedError.new("unreachable")
              end

    DNS.query(domain, records) do |record|
      # we need to skip non-target records like cnames
      if record.type.in?(records)
        # this seems to be the way to get a valid addrinfo
        ip_address = record.ip_address.address

        # NOTE:: ideally we set AI_NUMERICHOST, supported on all platforms, to ensure no blocking takes place
        # currently not possible in crystal as we don't have direct access to `ai_flags` field
        Crystal::System::Addrinfo.getaddrinfo(ip_address, service, family, type, protocol, timeout) do |addrinfo|
          yield addrinfo
        end
      end
    end
  end
end

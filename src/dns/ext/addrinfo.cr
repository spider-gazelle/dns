require "socket"
require "../../dns"

{% begin %}
struct Socket::Addrinfo
  QUERY_INET   = [DNS::Resource::A::RECORD_TYPE]
  QUERY_INET6  = [DNS::Resource::AAAA::RECORD_TYPE]
  QUERY_UNSPEC = [DNS::Resource::AAAA::RECORD_TYPE, DNS::Resource::A::RECORD_TYPE]

  private def self.getaddrinfo(domain, service, family, type, protocol, timeout,
    {% if compare_versions(Crystal::VERSION, "1.19.0") >= 0 %}
      flags = 0,
    {% end %}
  &)
    # fallback to the original implementation in these cases
    is_ip = Socket::IPAddress.valid?(domain)
    if is_ip || family.unix? || domain.includes?('/') || DNS.select_resolver(domain).is_a?(DNS::Resolver::System)
      domain = URI::Punycode.to_ascii domain
      Crystal::System::Addrinfo.getaddrinfo(domain, service, family, type, protocol, timeout,
        {% if compare_versions(Crystal::VERSION, "1.19.0") >= 0 %}
          is_ip ? ::LibC::AI_NUMERICHOST : 0
        {% end %}
      ) do |addrinfo|
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

    found = false
    DNS.query(domain, records) do |record|
      # we need to skip non-target records like cnames
      if record.type.in?(records)
        # this seems to be the way to get a valid addrinfo
        ip_address = record.ip_address.address
        found = true

        # We set AI_NUMERICHOST, supported on all platforms, to ensure no blocking takes place
        Crystal::System::Addrinfo.getaddrinfo(ip_address, service, family, type, protocol, timeout,
          {% if compare_versions(Crystal::VERSION, "1.19.0") >= 0 %}
            ::LibC::AI_NUMERICHOST
          {% end %}
        ) do |addrinfo|
          yield addrinfo
        end
      end
    end
    raise Socket::Addrinfo::Error.new(message: "Hostname lookup for #{domain} failed: No address found") unless found
    nil
  rescue error : ::DNS::Packet::Error
    raise Socket::Addrinfo::Error.new(message: "Hostname lookup for #{domain} failed: No address associated with hostname", cause: error)
  rescue error : ::IO::TimeoutError
    raise Socket::Addrinfo::Error.new(message: "Hostname lookup for #{domain} failed: No address found", cause: error)
  end
end
{% end %}

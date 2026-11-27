require "./udp"
require "./tls"

class DNS::Resolver::System < DNS::Resolver
  def initialize(@fallback = Resolver::UDP.new)
    @servers = @fallback.servers
  end

  # resolver for queries that are not A or AAAA
  property fallback : Resolver::UDP

  A     = RecordType::A.value
  AAAA  = RecordType::AAAA.value
  EMPTY = [] of Socket::Addrinfo

  # Perform the DNS query, fetching using request_id => record_type
  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    & : DNS::Packet ->
  )
    address_fetch = fetch.select { |_, type| type.in?({A, AAAA}) }
    fallback_fetch = fetch.reject { |_, type| type.in?({A, AAAA}) }

    # fetch records using the system query
    system_results = begin
      case address_fetch.size
      when 1
        family = address_fetch.values.first == A ? Socket::Family::INET : Socket::Family::INET6
        Socket::Addrinfo.tcp(domain, 443, family, timeout: timeout)
      when 2
        Socket::Addrinfo.tcp(domain, 443, Socket::Family::UNSPEC, timeout: timeout)
      else
        EMPTY
      end
    rescue ex : Socket::Addrinfo::Error
      raise DNS::Packet::NameError.new(ex.message, cause: ex)
    end

    # dress the results up as a DNS response
    records_by_type = system_results.map do |addrinfo|
      resource = case addrinfo.family
                 in .inet?
                   Resource::A.new(addrinfo.ip_address.address)
                 in .inet6?
                   Resource::AAAA.new(addrinfo.ip_address.address)
                 in .unix?, .unspec?
                   raise ArgumentError.new("unexpected Addrinfo#family response #{addrinfo.family}")
                 end

      Packet::ResourceRecord.new(domain, resource.record_type, ClassCode::Internet.value, 0.seconds, resource)
    end.group_by(&.type)

    address_fetch.each do |id, type|
      records = records_by_type[type]? || [] of Packet::ResourceRecord
      yield DNS::Packet.new(id: id, response: true, answers: records)
    end

    # perform any other queries
    unless fallback_fetch.empty?
      fallback.query(domain, dns_server, fallback_fetch, timeout) do |packet|
        yield packet
      end
    end
  end
end

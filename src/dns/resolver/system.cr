require "./udp"

class DNS::Resolver::System < DNS::Resolver
  def initialize(@fallback = Resolver::UDP.new)
    @servers = @fallback.servers
  end

  # resolver for queries that are not A or AAAA
  property fallback : Resolver::UDP

  A     = RecordType::A.value
  AAAA  = RecordType::AAAA.value
  EMPTY = [] of Socket::Addrinfo
  BLANK = Bytes.new(0)

  # Perform the DNS query, fetching using request_id => record_type
  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)
    fallback_fetch = nil
    fetch.select! do |req_id, record_type|
      next true if record_type.in?({A, AAAA})
      fallback_fetch ||= Hash(UInt16, UInt16).new
      fallback_fetch[req_id] = record_type
      nil
    end

    # fetch records using the system query
    system_results = begin
      case fetch.size
      when 1
        family = fetch.values.first == A ? Socket::Family::INET : Socket::Family::INET6
        Socket::Addrinfo.tcp(domain, 443, family)
      when 2
        Socket::Addrinfo.tcp(domain, 443, Socket::Family::UNSPEC)
      else
        EMPTY
      end
    rescue ex : Socket::Addrinfo::Error
      raise DNS::Packet::NameError.new(ex.message, cause: ex)
    end

    unless system_results.empty?
      records = system_results.map do |addrinfo|
        resource = case addrinfo.family
                   in .inet6?
                     Resource::AAAA.new(addrinfo.ip_address.address)
                   in .inet?
                     Resource::A.new(addrinfo.ip_address.address)
                   in .unix?, .unspec?
                     raise ArgumentError.new("unexpected Addrinfo#family #{addrinfo.family}")
                   end

        Packet::ResourceRecord.new(domain, resource.record_type, ClassCode::Internet.value, 0.seconds, BLANK, resource)
      end

      yield DNS::Packet.new(id: 0_u16, response: true, answers: records)
    end

    if fallback_fetch
      fallback.query(domain, dns_server, fallback_fetch) do |packet|
        yield packet
      end
    end
  end
end

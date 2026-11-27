require "socket"

class DNS::Resolver::MDNS < DNS::Resolver
  def initialize(
    @servers : Array(String) = ["224.0.0.251", "ff02::fb"],
    @port : UInt16 = 5353_u16,
    *,
    @ipv4_interface : String? = nil,
    @ipv6_interface : UInt32? = nil,
  )
    # mDNS doesn't use search domain expansion. Give low-powered devices extra
    # time to respond and keep to a single multicast pass per address.
    @server_config = DNS::Servers.new([] of String, attempts: 1)
  end

  def base_timeout : Time::Span
    server_config.timeout(DNS.timeout * 2)
  end

  # port to make the DNS query on, defaults to 5353
  property port : UInt16
  property ipv4_interface : String?
  property ipv6_interface : UInt32?

  # perform the DNS query, fetching using request_id => record_type
  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),

    # give mDNS a little more time to respond (low powered devices)
    timeout : Time::Span = base_timeout,
    & : DNS::Packet ->
  )
    return if fetch.empty?

    domain = domain.rchop('.')
    outstanding = fetch.values.to_set
    received_answer = false
    deadline = Time.instant + timeout
    ip = Socket::IPAddress.new(dns_server, port)
    socket = UDPSocket.new ip.family

    begin
      configure_socket(socket, ip.family)

      # pipeline the requests
      outstanding.each do |record|
        # query class set to Internet + QU bit for unicast responses
        # mDNS id's are always set to 0
        query_bytes = DNS::Packet::Question.build_query(domain, record, 0_u16, class_code: 0x8001_u16)
        socket.send query_bytes, ip
      end

      # process the responses
      buff = uninitialized UInt8[4096]
      buffer = buff.to_slice
      until outstanding.empty?
        dns_response = begin
          read_response(socket, buffer, deadline)
        rescue ex : IO::TimeoutError
          # One family can be absent from an otherwise successful lookup.
          return if received_answer
          raise ex
        end
        next unless dns_response

        matched_types = dns_response.answers.compact_map do |answer|
          if (answer.class_code & 0x7fff) == ClassCode::Internet.value && answer.name.compare(domain, case_insensitive: true) == 0
            answer.type if outstanding.includes?(answer.type)
          end
        end
        next if matched_types.empty?

        outstanding.subtract(matched_types)
        received_answer = true
        yield dns_response
      end
    ensure
      socket.close
    end
  end

  private def configure_socket(socket : UDPSocket, family : Socket::Family) : Nil
    if family.inet?
      socket.bind(Socket::IPAddress::UNSPECIFIED, 0)
      if address = ipv4_interface
        socket.multicast_interface(Socket::IPAddress.new(address, 0))
      end
    else
      socket.bind(Socket::IPAddress::UNSPECIFIED6, 0)
      if index = ipv6_interface
        socket.multicast_interface(index)
      end
    end
    socket.multicast_hops = 255
  end

  private def read_response(socket : UDPSocket, buffer : Bytes, deadline : Time::Instant) : DNS::Packet?
    socket.read_timeout = remaining_time(deadline)
    length, source = socket.receive(buffer)
    return if length.zero? || source.port != port

    begin
      packet = DNS::Packet.from_slice(buffer[0, length].dup)
      packet if packet.response? && packet.id.zero? && packet.operation_code.zero?
    rescue IO::Error
      nil
    end
  end
end

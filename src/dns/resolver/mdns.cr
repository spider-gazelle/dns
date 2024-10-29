require "socket"

class DNS::Resolver::MDNS < DNS::Resolver
  def initialize(@servers : Array(String) = ["224.0.0.251", "ff02::fb"], @port : UInt16 = 5353_u16)
  end

  # port to make the DNS query on, defaults to 53
  property port : UInt16

  # perform the DNS query, fetching using request_id => record_type
  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)
    ip = Socket::IPAddress.new(dns_server, port)
    socket = UDPSocket.new ip.family

    begin
      # bind to an unused port
      socket.bind(ip.family.inet? ? Socket::IPAddress::UNSPECIFIED : Socket::IPAddress::UNSPECIFIED6, 0)
      socket.multicast_hops = 255

      # give mDNS a little more time to respond (low powered devices)
      socket.read_timeout = DNS.timeout * 1.5

      # pipeline the requests
      fetch.each do |_id, record|
        # query class set to Internet + QU bit for unicast responses
        # mDNS id's are always set to 0
        query_bytes = DNS::Packet::Question.build_query(domain, record, 0_u16, class_code: 0x8001_u16)
        socket.send query_bytes, ip
      end

      # process the responses
      buff = uninitialized UInt8[4096]
      buffer = buff.to_slice
      responses = 0
      loop do
        received_length, _ip_address = socket.receive buffer
        raise IO::Error.new("mDNS query failed, zero bytes received") if received_length.zero?
        dns_response = DNS::Packet.from_slice buffer[0, received_length]

        # ignore anything we are not expecting
        if dns_response.answers.any? { |answer| answer.name.downcase == domain && answer.type.in?(fetch.values) }
          yield dns_response
          responses += 1
          break if responses == fetch.size
        end
      end
    ensure
      socket.close
    end
  end
end

# A minimal in-process DNS server used to exercise the UDP resolver's transport
# behavior with local sockets.
private class DNSStubSocket < UDPSocket
  def join_loopback_group(group : String)
    multicast = Socket::IPAddress.new(group, 0).@addr.as(LibC::InAddr)
    loopback = Socket::IPAddress.new("127.0.0.1", 0).@addr.as(LibC::InAddr)
    membership = LibC::IpMreq.new(imr_multiaddr: multicast, imr_interface: loopback)
    setsockopt(LibC::IP_ADD_MEMBERSHIP, membership, LibC::IPPROTO_IP)
  end
end

class DNSStub
  getter port : Int32
  getter source_ports = [] of Int32
  getter request_count = 0

  @tcp : TCPServer? = nil

  def initialize(@host = "127.0.0.1", port = 0, *, multicast_group : String? = nil)
    @udp = DNSStubSocket.new(Socket::IPAddress.new(@host, port).family)
    @udp.bind(@host, port)
    @udp.join_loopback_group(multicast_group) if multicast_group
    @port = @udp.local_address.port
  end

  # handler: (query, request_count, source) -> reply or nil to drop
  def serve_udp(&handler : DNS::Packet, Int32, Socket::IPAddress -> Bytes?)
    spawn do
      buffer = Bytes.new(4096)
      loop do
        length, source = @udp.receive(buffer)
        @request_count += 1
        @source_ports << source.port
        query = DNS::Packet.from_slice(buffer[0, length].dup)
        if reply = handler.call(query, @request_count, source)
          @udp.send(reply, source)
        end
      rescue IO::Error
        break
      rescue
        # ignore malformed datagrams in tests
      end
    end
  end

  def serve_tcp(&handler : DNS::Packet -> Bytes)
    server = TCPServer.new(@host, @port)
    @tcp = server
    spawn do
      while client = server.accept?
        handle_tcp(client, handler)
      end
    rescue IO::Error
    end
  end

  private def handle_tcp(client, handler)
    length = client.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    bytes = Bytes.new(length)
    client.read_fully(bytes)
    query = DNS::Packet.from_slice(bytes)
    response = handler.call(query)

    io = IO::Memory.new
    io.write_bytes(response.size.to_u16, IO::ByteFormat::BigEndian)
    io.write response
    client.write io.to_slice
    client.flush
  ensure
    client.close
  end

  def reply(bytes : Bytes, destination : Socket::IPAddress) : Nil
    @udp.send(bytes, destination)
  end

  def close
    @udp.close
    @tcp.try(&.close)
  end
end

def dns_response(
  query : DNS::Packet,
  *,
  truncated = false,
  answers = [] of DNS::Packet::ResourceRecord,
  id : UInt16? = nil,
  questions : Array(DNS::Packet::Question)? = nil,
  additionals = [] of DNS::Packet::ResourceRecord,
  authorities = [] of DNS::Packet::ResourceRecord,
  response_code = 0_u8,
  authenticated_data = false,
) : Bytes
  DNS::Packet.new(
    id: id || query.id,
    response: true,
    truncation: truncated,
    questions: questions || query.questions,
    answers: answers,
    additionals: additionals,
    authorities: authorities,
    response_code: response_code,
    authenticated_data: authenticated_data,
  ).to_slice
end

def a_answer(name = "example.com", ip = {93_u8, 184_u8, 216_u8, 34_u8})
  DNS::Packet::ResourceRecord.new(name, 1_u16, 1_u16, 60.seconds, resource_data: Bytes[ip[0], ip[1], ip[2], ip[3]])
end

def udp_resolver(stub, *, timeout = 2.seconds, attempts = 1)
  resolver = DNS::Resolver::UDP.new(["127.0.0.1"], port: stub.port.to_u16)
  resolver.server_config = DNS::Servers.new(["127.0.0.1"], timeout: timeout, attempts: attempts)
  resolver
end

def aaaa_answer(name : String)
  data = "20010db8000000000000000000000001".hexbytes
  DNS::Packet::ResourceRecord.new(name, 28_u16, 1_u16, 60.seconds, resource_data: data)
end

def domain_answer(name : String, type : DNS::RecordType, target : String)
  data = IO::Memory.new
  DNS::Resource.write_labels(data, target)
  DNS::Packet::ResourceRecord.new(name, type.value, 1_u16, 60.seconds, resource_data: data.to_slice)
end

require "socket"

class DNS::Resolver::TLS < DNS::Resolver
  # provide your own server list
  def initialize(@server_names : Hash(String, String), @port : UInt16 = 853_u16)
    @servers = @server_names.keys
  end

  # mapping of IP addresses to TLS names
  getter server_names : Hash(String, String)

  # port to make the DNS query on, defaults to 53
  property port : UInt16

  # perform the DNS query, fetching using request_id => record_type
  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)
    dns_server_name = server_names[dns_server]
    ip = Socket::IPAddress.new(dns_server, port)
    socket = TCPSocket.new ip.family
    socket.read_timeout = DNS.timeout
    socket.tcp_nodelay = true

    begin
      socket.connect(ip)
      socket = OpenSSL::SSL::Socket::Client.new(socket, sync_close: true, hostname: dns_server_name)

      # pipeline the requests
      fetch.each do |id, record|
        io = IO::Memory.new
        query_bytes = DNS::Packet::Question.build_query(domain, record, id)
        io.write_bytes(query_bytes.size.to_u16, IO::ByteFormat::BigEndian)
        io.write query_bytes

        # ensure request sent in a single write system call
        socket.write(io.to_slice)
        socket.flush
      end

      # process the responses
      responses = 0
      loop do
        message_length = socket.read_bytes UInt16, IO::ByteFormat::BigEndian
        message_bytes = Bytes.new(message_length)
        socket.read_fully message_bytes
        dns_response = DNS::Packet.from_slice message_bytes

        # ignore anything we are not expecting
        if fetch[dns_response.id]?
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

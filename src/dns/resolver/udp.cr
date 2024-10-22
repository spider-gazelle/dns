require "socket"

class DNS::Resolver::UDP < DNS::Resolver
  class_getter system_servers : Array(String) do
    dns_servers = [] of String
    File.open("/etc/resolv.conf") do |file|
      file.each_line do |line|
        if line =~ /^\s*nameserver\s+([^\s]+)/
          dns_servers << $1
        end
      end
    end
    dns_servers
  rescue ex : Exception
    [] of String
  end

  class_property fallback_servers : Array(String) { ["1.1.1.1", "8.8.8.8"] }

  # provide your own server list
  def initialize(@servers : Array(String), @port : UInt16 = 53_u16)
  end

  # attempts to use system server list or fallback servers if unavailable
  def initialize(@port : UInt16 = 53_u16)
    servers = self.class.system_servers
    servers = self.class.fallback_servers if servers.empty?
    @servers = servers
  end

  # port to make the DNS query on, defaults to 53
  property port : UInt16

  # perform the DNS query, fetching using request_id => record_code
  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)
    ip = Socket::IPAddress.new(dns_server, port)
    socket = UDPSocket.new ip.family

    begin
      socket.connect(dns_server, port)
      socket.read_timeout = DNS.timeout

      # pipeline the requests
      fetch.each do |id, record|
        query_bytes = DNS::Packet::Question.build_query(domain, record, id)
        socket.send(query_bytes)
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

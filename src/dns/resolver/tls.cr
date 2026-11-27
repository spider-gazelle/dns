require "socket"
require "openssl"

class DNS::Resolver::TLS < DNS::Resolver
  # provide your own server list
  def initialize(@server_names : Hash(String, String), @port : UInt16 = 853_u16, @tls_context : OpenSSL::SSL::Context::Client? = nil)
    @servers = @server_names.keys
  end

  # mapping of IP addresses to TLS names
  getter server_names : Hash(String, String)

  # port to make the DNS query on, defaults to 853
  property port : UInt16

  # perform the DNS query, fetching using request_id => record_type
  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    & : DNS::Packet ->
  )
    query(domain, dns_server, fetch, timeout, dnssec: DNSSEC::Options.new) { |response| yield response }
  end

  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    *,
    dnssec : DNSSEC::Options,
    & : DNS::Packet ->
  )
    return if fetch.empty?

    dns_server_name = server_names[dns_server]
    ip = Socket::IPAddress.new(dns_server, port)
    deadline = Time.instant + timeout
    socket = TCPSocket.new ip.family
    tls_socket : OpenSSL::SSL::Socket::Client? = nil

    begin
      socket.tcp_nodelay = true
      socket.connect(ip, timeout: remaining_time(deadline))
      socket.read_timeout = socket.write_timeout = remaining_time(deadline)
      context = @tls_context || OpenSSL::SSL::Context::Client.new
      tls_socket = OpenSSL::SSL::Socket::Client.new(socket, context, hostname: dns_server_name)

      # pipeline the requests
      fetch.each do |id, record|
        query_bytes = DNS::Packet::Question.build_query(domain, record, id, edns: query_edns, dnssec: dnssec)
        write_tcp_query(tls_socket, query_bytes, deadline)
      end

      outstanding = fetch.dup
      until outstanding.empty?
        dns_response = read_tcp_response(tls_socket, deadline)
        if (record = outstanding[dns_response.id]?) &&
           dns_response.matches_question?(domain, record, dns_response.id, allow_missing_question: true)
          outstanding.delete(dns_response.id)
          yield dns_response
        end
      end
    rescue ex : OpenSSL::Error
      raise IO::Error.new("DNS-over-TLS query to #{dns_server} failed", cause: ex)
    ensure
      begin
        tls_socket.try(&.close)
      ensure
        socket.close
      end
    end
  end
end

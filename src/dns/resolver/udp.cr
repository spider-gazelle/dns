require "socket"
require "random/secure"

class DNS::Resolver::UDP < DNS::Resolver
  # EDNS0 advertised UDP payload size. 1232 = 1280 (IPv6 min MTU) - 48 (IPv6+UDP
  # headers), the DNS Flag Day 2020 recommendation that avoids IP fragmentation.
  alias EDNS = DNS::Packet::EDNS

  EDNS_UDP_SIZE = EDNS::DEFAULT_UDP_SIZE

  # DNS Cookies are negotiated separately with each UDP upstream.
  property? dns_cookies : Bool = true
  @cookie_jar = CookieJar.new

  # provide your own server list
  def initialize(@servers : Array(String), @port : UInt16 = 53_u16)
  end

  # attempts to use system server list or fallback servers if unavailable
  def initialize(@port : UInt16 = 53_u16)
    servers = server_config.servers
    servers = Servers.fallback if servers.empty?
    @servers = servers
  end

  # port to make the DNS query on, defaults to 53
  property port : UInt16

  # perform the DNS query, fetching using request_id => record_type
  #
  # All UDP traffic flows over a single, long-lived, process-wide source port
  # (see `SharedSocket`); responses are demultiplexed back to this call by
  # transaction id. Returns once every question has a response, otherwise raises
  # `IO::TimeoutError` so the caller can retry / fail over to another server.
  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    & : DNS::Packet ->
  )
    return if fetch.empty?

    server = Socket::IPAddress.new(dns_server, port.to_i)
    peer = cookie_peer(server) if managed_cookies?
    cookie = @cookie_jar.option(peer) if peer
    edns = udp_edns(cookie)
    legacy = edns_options.empty? && (!cookie || cookie.data.size == CookieJar::CLIENT_SIZE)
    exchange = Exchange.new(server, domain, fetch, timeout, legacy: legacy, cookie_peer: peer)
    fetch.each { |id, type| exchange.send(id, type, edns) }

    until exchange.outstanding.empty?
      reply = exchange.receive || raise IO::TimeoutError.new("DNS query to #{dns_server} did not complete in time")
      next unless response = process_reply(exchange, reply)
      exchange.complete(response.id)
      yield response
    end
  ensure
    exchange.try(&.close)
  end

  private def managed_cookies? : Bool
    dns_cookies? && edns_options.none? { |option| option.code == EDNS::COOKIE }
  end

  private def cookie_peer(server : Socket::IPAddress) : CookieJar::Peer?
    # Ask the kernel which local address it routes to this server. UDP connect
    # sends no packet. DNS messages still use the long-lived shared socket.
    route = UDPSocket.new(server.family)
    route.connect(server)
    source = route.local_address
    address = source.address
    if interface = source.link_local_interface
      address = "#{address}%#{interface}"
    end
    CookieJar::Peer.new(server, address)
  rescue IO::Error
    nil
  ensure
    route.try(&.close)
  end

  private def udp_edns(cookie : EDNS::Option?) : EDNS
    cookie ? EDNS.new(options: edns_options + [cookie]) : query_edns
  end

  private def process_reply(exchange : Exchange, reply : SharedSocket::Reply) : DNS::Packet?
    packet = reply.packet
    return unless type = exchange.outstanding[packet.id]?
    return unless reply.edns || exchange.legacy?

    if (cookie = learn_cookie(exchange, reply)) && packet.effective_response_code == CookieJar::BAD_COOKIE && exchange.cookie_peer
      return retry_cookie(exchange, packet.id, type, cookie)
    end

    if packet.truncation? && !packet.edns_rejected?
      packet = refetch(exchange, type, packet.id, reply.edns ? EDNS_UDP_SIZE : 0_u16)
    end

    return if exchange.retry_legacy?(reply, packet)

    packet
  end

  private def learn_cookie(exchange : Exchange, reply : SharedSocket::Reply) : EDNS::Option?
    sent = reply.edns.try(&.option(EDNS::COOKIE))
    return unless sent

    cookie = reply.packet.edns.try(&.option(EDNS::COOKIE))
    exchange.require_edns if cookie
    if peer = exchange.cookie_peer
      @cookie_jar.remember(peer, sent, cookie)
    end
    cookie
  end

  private def retry_cookie(exchange : Exchange, id : UInt16, type : UInt16, cookie : EDNS::Option) : DNS::Packet?
    return refetch(exchange, type, id, EDNS_UDP_SIZE) unless exchange.retry_cookie?(id)
    exchange.send(id, type, udp_edns(cookie))
    nil
  end

  private def refetch(exchange : Exchange, type : UInt16, id : UInt16, udp_size : UInt16) : DNS::Packet
    server = exchange.server
    tcp_query(server, exchange.domain, id, type, remaining_time(exchange.deadline), edns_udp_size: udp_size) ||
      raise IO::Error.new("DNS TCP fallback failed for #{server.address}")
  end

  # refetch a single question over TCP (used when a UDP response is truncated).
  # returns nil on any transport/parse/validation failure so the caller can
  # fail over rather than crash.
  protected def tcp_query(
    server : Socket::IPAddress,
    domain : String,
    id : UInt16,
    record : UInt16,
    timeout : Time::Span,
    *,
    edns_udp_size : UInt16 = EDNS_UDP_SIZE,
  ) : DNS::Packet?
    deadline = Time.instant + timeout
    socket = TCPSocket.new(server.family)

    begin
      socket.tcp_nodelay = true
      socket.connect(server, timeout: remaining_time(deadline))
      edns = EDNS.new(edns_udp_size, edns_options) unless edns_udp_size.zero?
      query = DNS::Packet::Question.build_query(domain, record, id, edns: edns)
      write_tcp_query(socket, query, deadline)

      packet = read_tcp_response(socket, deadline)
      allow_missing_question = !edns_udp_size.zero? && packet.edns_rejected?
      packet if !packet.truncation? && packet.matches_question?(domain, record, id, allow_missing_question: allow_missing_question)
    rescue ex : IO::Error
      Log.trace(exception: ex) { "TCP fallback to #{server} failed" }
      nil
    ensure
      socket.close
    end
  end

  # A process-wide singleton owning the shared UDP source port(s), a background
  # reader fiber per address family, and the registry of in-flight requests.
  #
  # Reusing a single source port (rather than a fresh ephemeral port per query)
  # trades source-port entropy for connection reuse. To keep this safe against
  # off-path spoofing (RFC 5452) every response must pass strict validation:
  # the wire transaction id must be registered, QR must be set, the source
  # address must equal the queried server, and the echoed question must match.
  class SharedSocket
    class_getter instance : SharedSocket { SharedSocket.new }

    record Reply, packet : DNS::Packet, edns : EDNS?

    # max bytes read from a single datagram; a larger answer arrives truncated
    # (TC) and is refetched over TCP
    RECV_BUFFER_SIZE = 4096

    # cap on concurrent in-flight queries (half the 16-bit id space) so wire-id
    # allocation never degrades into a long collision-retry loop under the mutex
    MAX_INFLIGHT = 32_768

    private class Pending
      getter channel : Channel(Reply)
      getter server : Socket::IPAddress
      getter name : String
      getter type : UInt16
      getter logical_id : UInt16
      getter edns : EDNS?
      property? delivered : Bool = false

      def initialize(@channel, @server, @name, @type, @logical_id, @edns)
      end

      def matches?(packet : DNS::Packet, wire_id : UInt16) : Bool
        sent = edns.try(&.option(EDNS::COOKIE))
        return false unless CookieJar.accepts?(sent, packet)

        compatibility_reply = edns && packet.edns_rejected?
        cookie_challenge = sent && packet.effective_response_code == CookieJar::BAD_COOKIE
        allow_missing_question = !!(compatibility_reply || cookie_challenge)
        packet.matches_question?(name, type, wire_id, allow_missing_question: allow_missing_question)
      end
    end

    def initialize
      @mutex = Mutex.new
      @pending = Hash(UInt16, Pending).new
      @v4 = nil.as(UDPSocket?)
      @v6 = nil.as(UDPSocket?)
    end

    # send a single question over the shared socket and register it for response
    # delivery; returns the wire transaction id used.
    def register_and_send(
      server : Socket::IPAddress,
      domain : String,
      logical_id : UInt16,
      record : UInt16,
      channel : Channel(Reply),
      *,
      edns : EDNS?,
    ) : UInt16
      socket = socket_for(server.family)

      # allocate a globally-unique, unpredictable wire id and register atomically.
      # capping in-flight at half the id space keeps this collision loop O(1).
      wire_id = @mutex.synchronize do
        raise IO::Error.new("too many in-flight DNS queries (#{@pending.size})") if @pending.size >= MAX_INFLIGHT
        id = Random::Secure.rand(UInt16)
        while @pending.has_key?(id)
          id = Random::Secure.rand(UInt16)
        end
        @pending[id] = Pending.new(channel, server, domain, record, logical_id, edns)
        id
      end

      begin
        query_bytes = DNS::Packet::Question.build_query(domain, record, wire_id, edns: edns)
        socket.send(query_bytes, server)
      rescue ex
        cancel({wire_id})
        raise ex
      end

      wire_id
    end

    # deregister in-flight requests (on completion, timeout or send failure)
    def cancel(wire_ids : Enumerable(UInt16)) : Nil
      @mutex.synchronize { wire_ids.each { |id| @pending.delete(id) } }
    end

    private def socket_for(family : Socket::Family) : UDPSocket
      @mutex.synchronize do
        case family
        when .inet?
          @v4 ||= open_socket(Socket::Family::INET, Socket::IPAddress::UNSPECIFIED)
        when .inet6?
          @v6 ||= open_socket(Socket::Family::INET6, Socket::IPAddress::UNSPECIFIED6)
        else
          raise ArgumentError.new("unsupported address family for UDP DNS: #{family}")
        end
      end
    end

    private def open_socket(family : Socket::Family, bind_host : String) : UDPSocket
      socket = UDPSocket.new(family)
      # bind once to an OS-assigned ephemeral port shared by every query
      begin
        socket.bind(bind_host, 0)
      rescue ex
        socket.close
        raise ex
      end
      spawn { read_loop(socket) }
      socket
    end

    # background fiber: receive datagrams and route them to waiting queries
    private def read_loop(socket : UDPSocket) : Nil
      buffer = Bytes.new(RECV_BUFFER_SIZE)
      loop do
        length, source = socket.receive(buffer)
        next if length.zero?
        handle_datagram(buffer[0, length], source)
      end
    rescue ex : IO::Error
      Log.trace(exception: ex) { "DNS shared socket stopped receiving" }
    ensure
      @mutex.synchronize do
        @v4 = nil if @v4.same?(socket)
        @v6 = nil if @v6.same?(socket)
      end
      socket.close
    end

    private def handle_datagram(bytes : Bytes, source : Socket::IPAddress) : Nil
      # cheaply read the transaction id from the header and look it up BEFORE the
      # full parse, so unsolicited / junk datagrams cost almost nothing
      return if bytes.size < 12 # smaller than a DNS header
      wire_id = (bytes[0].to_u16 << 8) | bytes[1].to_u16

      pending = @mutex.synchronize do
        request = @pending[wire_id]?
        request if request && !request.delivered?
      end
      return unless pending && source == pending.server

      packet = begin
        DNS::Packet.from_slice(bytes.dup)
      rescue ex
        Log.trace(exception: ex) { "discarding invalid UDP DNS response" }
        return
      end
      return unless pending.matches?(packet, wire_id)

      # Reserve the ID until its owner cleans up, and ignore duplicates.
      @mutex.synchronize do
        return if pending.delivered? || !@pending[wire_id]?.same?(pending)
        pending.delivered = true
      end
      packet.id = pending.logical_id
      select
      when pending.channel.send(Reply.new(packet, pending.edns))
        # delivered
      else
        # waiter already gone / buffer full: drop rather than block the reader
      end
    rescue Channel::ClosedError
      # the waiting query went away; nothing to deliver to
    end
  end
end

require "./udp/*"

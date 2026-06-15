require "socket"
require "random/secure"

class DNS::Resolver::UDP < DNS::Resolver
  # EDNS0 advertised UDP payload size. 1232 = 1280 (IPv6 min MTU) - 48 (IPv6+UDP
  # headers), the DNS Flag Day 2020 recommendation that avoids IP fragmentation.
  EDNS_UDP_SIZE = 1232_u16

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
    shared = SharedSocket.instance

    # one buffered slot per outstanding question so the reader never blocks
    channel = Channel(DNS::Packet).new(fetch.size)
    wire_ids = Array(UInt16).new(fetch.size)

    begin
      fetch.each do |logical_id, record|
        wire_ids << shared.register_and_send(server, domain, logical_id, record, channel)
      end

      deadline = Time.instant + timeout
      received = 0
      while received < fetch.size
        remaining = deadline - Time.instant
        break if remaining <= Time::Span.zero

        response =
          select
          when packet = channel.receive
            packet
          when timeout(remaining)
            nil # overall deadline reached
          end
        break if response.nil?

        received += 1

        # a truncated UDP response (TC bit) must be refetched over TCP to obtain
        # the complete answer (RFC 7766 / DNS Flag Day 2020). If the TCP fetch
        # fails we must NOT yield the partial UDP answer - raise so the caller
        # retries / fails over to another server.
        if response.truncation?
          record = fetch[response.id]?
          tcp = record ? tcp_query(server, domain, response.id, record, timeout) : nil
          raise IO::Error.new("truncated DNS response and TCP fallback failed for #{dns_server}") unless tcp
          response = tcp
        end

        yield response
      end

      raise IO::TimeoutError.new("DNS query to #{dns_server} did not complete in time") if received < fetch.size
    ensure
      shared.cancel(wire_ids)
    end
  end

  # refetch a single question over TCP (used when a UDP response is truncated).
  # returns nil on any transport/parse/validation failure so the caller can
  # fail over rather than crash.
  protected def tcp_query(server : Socket::IPAddress, domain : String, id : UInt16, record : UInt16, timeout : Time::Span) : DNS::Packet?
    socket = TCPSocket.new(server.family)
    socket.read_timeout = timeout
    socket.write_timeout = timeout
    socket.tcp_nodelay = true

    begin
      socket.connect(server)

      # TCP DNS messages are length-prefixed with a 16-bit big-endian length
      query_bytes = DNS::Packet::Question.build_query(domain, record, id, edns_udp_size: EDNS_UDP_SIZE)
      io = IO::Memory.new
      io.write_bytes(query_bytes.size.to_u16, IO::ByteFormat::BigEndian)
      io.write query_bytes
      socket.write(io.to_slice)
      socket.flush

      message_length = socket.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      return nil if message_length.zero?
      message_bytes = Bytes.new(message_length)
      socket.read_fully(message_bytes)
      packet = DNS::Packet.from_slice(message_bytes)

      # validate the response matches the request we sent (the connected socket
      # guarantees the peer, but we still verify id + question for correctness)
      return nil unless packet.response? && packet.id == id
      question = packet.questions.first?
      return nil unless question && question.type == record
      return nil unless question.class_code == DNS::ClassCode::Internet.value
      return nil unless question.name.downcase == domain
      packet
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

    # max bytes read from a single datagram; a larger answer arrives truncated
    # (TC) and is refetched over TCP
    RECV_BUFFER_SIZE = 4096

    # cap on concurrent in-flight queries (half the 16-bit id space) so wire-id
    # allocation never degrades into a long collision-retry loop under the mutex
    MAX_INFLIGHT = 32_768

    # an in-flight request awaiting its response
    private record Pending,
      channel : Channel(DNS::Packet),
      server : Socket::IPAddress,
      name : String,
      type : UInt16,
      logical_id : UInt16

    def initialize
      @mutex = Mutex.new
      @pending = Hash(UInt16, Pending).new
      @v4 = nil.as(UDPSocket?)
      @v6 = nil.as(UDPSocket?)
    end

    # send a single question over the shared socket and register it for response
    # delivery; returns the wire transaction id used.
    def register_and_send(server : Socket::IPAddress, domain : String, logical_id : UInt16, record : UInt16, channel : Channel(DNS::Packet)) : UInt16
      socket = socket_for(server.family)

      # allocate a globally-unique, unpredictable wire id and register atomically.
      # capping in-flight at half the id space keeps this collision loop O(1).
      wire_id = @mutex.synchronize do
        raise IO::Error.new("too many in-flight DNS queries (#{@pending.size})") if @pending.size >= MAX_INFLIGHT
        id = Random::Secure.rand(UInt16)
        while @pending.has_key?(id)
          id = Random::Secure.rand(UInt16)
        end
        @pending[id] = Pending.new(channel, server, domain, record, logical_id)
        id
      end

      begin
        query_bytes = DNS::Packet::Question.build_query(domain, record, wire_id, edns_udp_size: EDNS_UDP_SIZE)
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
      socket.bind(bind_host, 0)
      spawn { read_loop(socket) }
      socket
    end

    # background fiber: receive datagrams and route them to waiting queries
    private def read_loop(socket : UDPSocket) : Nil
      buffer = Bytes.new(RECV_BUFFER_SIZE)
      loop do
        begin
          length, source = socket.receive(buffer)
          next if length.zero?
          # copy out of the reused buffer before handing across the channel
          handle_datagram(buffer[0, length].dup, source)
        rescue IO::Error
          break # socket closed / unrecoverable: stop reading
        rescue ex
          Log.warn(exception: ex) { "error processing DNS response on shared socket" }
        end
      end
    end

    private def handle_datagram(bytes : Bytes, source : Socket::IPAddress) : Nil
      # cheaply read the transaction id from the header and look it up BEFORE the
      # full parse, so unsolicited / junk datagrams cost almost nothing
      return if bytes.size < 12 # smaller than a DNS header
      wire_id = (bytes[0].to_u16 << 8) | bytes[1].to_u16

      pending = @mutex.synchronize { @pending[wire_id]? }
      return unless pending

      packet = DNS::Packet.from_slice(bytes)

      # RFC 5452 response validation - drop anything that doesn't match exactly
      return unless packet.response?
      return unless source == pending.server
      question = packet.questions.first?
      return unless question
      return unless question.type == pending.type
      return unless question.class_code == DNS::ClassCode::Internet.value
      return unless question.name.downcase == pending.name

      # accept: deregister (so duplicates/late replies are ignored) then deliver
      # with the wire id remapped back to the caller's logical request id.
      # the send is non-blocking: the reader fiber must never stall (the channel
      # is sized to the query's question count, so this practically always sends)
      @mutex.synchronize { @pending.delete(wire_id) }
      packet.id = pending.logical_id
      select
      when pending.channel.send(packet)
        # delivered
      else
        # waiter already gone / buffer full: drop rather than block the reader
      end
    rescue Channel::ClosedError
      # the waiting query went away; nothing to deliver to
    end
  end
end

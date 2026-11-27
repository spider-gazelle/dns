# an interface for interacting with DNS servers
abstract class DNS::Resolver
  @@next_cache_scope = Atomic(UInt64).new(0_u64)
  @@bootstrap_hosts = {} of Fiber => String
  @@bootstrap_lock = Mutex.new

  # Keeps network results from one resolver from satisfying another's queries.
  getter cache_scope : UInt64 = @@next_cache_scope.add(1_u64)

  # :nodoc:
  def self.with_system_resolution(hostname : String, &)
    fiber = Fiber.current
    previous = @@bootstrap_lock.synchronize do
      old = @@bootstrap_hosts[fiber]?
      @@bootstrap_hosts[fiber] = hostname.rchop('.').downcase
      old
    end
    yield
  ensure
    if fiber
      @@bootstrap_lock.synchronize do
        if previous
          @@bootstrap_hosts[fiber] = previous
        else
          @@bootstrap_hosts.delete(fiber)
        end
      end
    end
  end

  # :nodoc:
  def self.system_resolution?(hostname : String) : Bool
    @@bootstrap_lock.synchronize do
      @@bootstrap_hosts[Fiber.current]? == hostname.rchop('.').downcase
    end
  end

  @servers : Array(String) = [] of String
  @servers_lock : Mutex = Mutex.new
  @failure_counts : Hash(String, Int32) = Hash(String, Int32).new(0)

  property failure_limit : Int32 = 2

  # Explicit options for the unicast DNS transports. They are kept on retries.
  property edns_options = [] of DNS::Packet::EDNS::Option

  protected def query_edns : DNS::Packet::EDNS
    DNS::Packet::EDNS.new(options: edns_options)
  end

  # Server configuration including search domains and ndots for name expansion
  property server_config : DNS::Servers = DNS::Servers.host

  # perform the DNS query, fetching using request_id => record_type
  abstract def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), timeout : Time::Span, & : DNS::Packet ->)

  # Resolvers that expose wire-level DNSSEC flags override this overload.
  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span,
    *,
    dnssec : DNSSEC::Options,
    & : DNS::Packet ->
  )
    if dnssec.requested?
      raise DNSSEC::UnsupportedResolver.new("#{self.class} does not expose DNSSEC query flags")
    end
    query(domain, dns_server, fetch, timeout) { |response| yield response }
  end

  # returns the list of DNS servers and their current ordering
  def servers
    @servers_lock.synchronize { @servers.dup }
  end

  # returns the current failure counts for the servers
  def failure_counts
    @servers_lock.synchronize { @failure_counts.dup }
  end

  protected def reset_failure_count(server : String) : Nil
    @servers_lock.synchronize { @failure_counts[server] = 0 }
  end

  protected def increment_failure_count(server : String)
    Log.trace { "DNS timeout communicating with #{server}" }
    @servers_lock.synchronize { @failure_counts[server] += 1 }
  end

  protected def demote_server(index : Int32, servers : Array(String))
    server = servers.delete_at(index)
    servers << server
    Log.trace { "demoting DNS server: #{server}, DNS server ordering updated" }

    # duplicate outside of lock for efficiency
    # and also reset the failure count
    new_server_order = servers.dup
    @servers_lock.synchronize do
      @servers = new_server_order
      @failure_counts[server] = 0
    end
  end

  # number of whole-list query passes before giving up (resolv.conf `attempts:`)
  def attempts : Int32
    server_config.attempts
  end

  # the base (initial) per-try timeout (resolv.conf `timeout:`)
  def base_timeout : Time::Span
    server_config.timeout
  end

  # per-try timeout for a given attempt: exponential backoff capped at 30s
  # (modelled on the unix resolver's retransmission schedule)
  protected def timeout_for(attempt : Int32) : Time::Span
    (base_timeout * (2 ** attempt)).clamp(1.second, 30.seconds)
  end

  protected def remaining_time(deadline : Time::Instant) : Time::Span
    remaining = deadline - Time.instant
    raise IO::TimeoutError.new("DNS query did not complete in time") if remaining <= Time::Span.zero
    remaining
  end

  protected def write_tcp_query(socket, query : Bytes, deadline : Time::Instant) : Nil
    message = IO::Memory.new
    message.write_bytes(query.size.to_u16, IO::ByteFormat::BigEndian)
    message.write(query)
    socket.write_timeout = remaining_time(deadline)
    socket.write(message.to_slice)
    socket.flush
  end

  protected def read_tcp_response(socket, deadline : Time::Instant) : DNS::Packet
    prefix = Bytes.new(2)
    read_tcp_bytes(socket, prefix, deadline)
    length = IO::ByteFormat::BigEndian.decode(UInt16, prefix)
    bytes = Bytes.new(length)
    read_tcp_bytes(socket, bytes, deadline)
    DNS::Packet.from_slice(bytes)
  end

  private def read_tcp_bytes(socket, bytes : Bytes, deadline : Time::Instant) : Nil
    until bytes.empty?
      socket.read_timeout = remaining_time(deadline)
      count = socket.read(bytes)
      raise IO::EOFError.new if count.zero?
      bytes = bytes[count..]
    end
  end

  # yields the server (and the timeout to use) for a DNS lookup, retrying across
  # the configured nameservers.
  #
  # Modelled on glibc/getaddrinfo: `attempts` whole-list passes over the
  # nameservers, each pass using a longer (backed-off) timeout. A persistently
  # failing server is demoted to the end of the list (see `failure_limit`) so
  # future queries prefer healthy servers.
  def select_server(& : (String, Time::Span) ->) : Nil
    servers = self.servers
    raise IO::Error.new("no DNS servers configured") if servers.empty?

    error : Exception? = nil

    attempts.times do |attempt|
      timeout = timeout_for(attempt)

      # try each server once this pass, in the current (demotion-aware) order
      tried = 0
      index = 0
      while tried < servers.size
        server = servers[index]

        begin
          yield server, timeout

          # success: reset the failure count and stop
          reset_failure_count server
          return
        rescue ex : IO::TimeoutError
          error = ex
          Log.trace(exception: ex) { "timeout against #{server}" }
          demote = increment_failure_count(server) >= failure_limit
        rescue ex : IO::Error | DNS::Packet::ServerError
          error = ex
          Log.trace(exception: ex) { "IO or Packet error against #{server}" }
          demote = true
        end

        if demote
          # move the bad server to the end; the next server shifts into `index`
          demote_server(index, servers)
        else
          index += 1
        end
        tried += 1
      end
    end

    raise error if error
  end
end

require "./resolver/udp"
require "./resolver/tls"
require "./resolver/mdns"
require "./resolver/system"
require "./resolver/validating"

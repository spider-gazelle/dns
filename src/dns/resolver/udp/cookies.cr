require "crypto/subtle"

class DNS::Resolver::UDP
  private class CookieJar
    CLIENT_SIZE =      8
    BAD_COOKIE  = 23_u16
    MAX_SERVERS =   1024

    record Peer, server : Socket::IPAddress, source : String
    private record Entry, data : Bytes?, expires : Time::Instant

    @lock = Mutex.new
    @cookies = {} of Peer => Entry

    def option(peer : Peer) : EDNS::Option?
      data = @lock.synchronize do
        if (entry = @cookies[peer]?) && Time.instant < entry.expires
          return unless cached = entry.data
          cached
        else
          Random::Secure.random_bytes(CLIENT_SIZE)
        end
      end
      EDNS::Option.new(EDNS::COOKIE, data)
    end

    def remember(peer : Peer, sent : EDNS::Option, received : EDNS::Option?) : Nil
      now = Time.instant
      @lock.synchronize do
        current = @cookies[peer]?
        expires = now + 7.days
        # An older in-flight reply must not replace a newer negotiated cookie.
        if current && now < current.expires && (data = current.data)
          return unless data == sent.data
          expires = current.expires
        end
        @cookies.shift if !current && @cookies.size >= MAX_SERVERS
        if received
          @cookies[peer] = Entry.new(received.data.dup, expires)
        else
          # Avoid repeating probes to servers that ignore COOKIE (RFC 9018).
          @cookies[peer] = Entry.new(nil, now + 5.minutes)
        end
      end
    end

    def self.accepts?(sent : EDNS::Option?, packet : DNS::Packet) : Bool
      return true unless sent
      received = packet.edns.try(&.option(EDNS::COOKIE))
      return sent.data.size == CLIENT_SIZE && packet.effective_response_code != BAD_COOKIE unless received

      received.data.size.in?(16..40) && sent.data.size >= CLIENT_SIZE &&
        Crypto::Subtle.constant_time_compare(sent.data[0, CLIENT_SIZE], received.data[0, CLIENT_SIZE])
    end
  end
end

class DNS::Resolver::UDP
  # Owns the wire registrations and retry state for one server attempt.
  private class Exchange
    getter server : Socket::IPAddress
    getter domain : String
    getter deadline : Time::Instant
    getter outstanding : Hash(UInt16, UInt16)
    getter? legacy : Bool
    getter cookie_peer : CookieJar::Peer?
    getter dnssec : DNSSEC::Options

    @wire_ids = [] of UInt16
    @cookie_retries = Set(UInt16).new
    @shared : SharedSocket = SharedSocket.instance
    @legacy_probes : Hash(UInt16, UInt16)

    def initialize(@server, @domain, fetch : Hash(UInt16, UInt16), timeout : Time::Span, @dnssec, @legacy : Bool, @cookie_peer)
      @outstanding = fetch.dup
      @legacy_probes = legacy? ? fetch.dup : {} of UInt16 => UInt16
      @channel = Channel(SharedSocket::Reply).new(fetch.size * 3)
      @deadline = Time.instant + timeout
      @probe_deadline = @deadline - timeout / 2
    end

    def send(id : UInt16, type : UInt16, edns : EDNS?) : Nil
      @wire_ids << @shared.register_and_send(server, domain, id, type, @channel, edns: edns, dnssec: dnssec)
    end

    def receive : SharedSocket::Reply?
      loop do
        limit = @legacy_probes.empty? ? deadline : @probe_deadline
        if (remaining = limit - Time.instant) > Time::Span.zero
          select
          when reply = @channel.receive
            return reply
          when timeout(remaining)
          end
        end

        return if @legacy_probes.empty? || Time.instant >= deadline

        # Keep the original IDs to accept a slow EDNS reply after the retry.
        @legacy_probes.each { |id, type| send(id, type, nil) }
        @legacy_probes.clear
      end
    end

    def retry_legacy?(reply : SharedSocket::Reply, response : DNS::Packet) : Bool
      return false unless legacy? && reply.edns && response.edns_rejected?
      id = response.id
      @legacy_probes.delete(id).try { |type| send(id, type, nil) }
      true
    end

    def require_edns : Nil
      @legacy = false
      @legacy_probes.clear
    end

    def retry_cookie?(id : UInt16) : Bool
      @cookie_retries.add?(id)
    end

    def complete(id : UInt16) : Nil
      @legacy_probes.delete(id)
      outstanding.delete(id)
    end

    def close : Nil
      @shared.cancel(@wire_ids)
    end
  end
end

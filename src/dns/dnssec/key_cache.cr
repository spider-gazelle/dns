module DNS::DNSSEC
  # Track wall time for signature validity and monotonic time for TTL aging.
  # :nodoc:
  record KeyExpiry, wall : Time, monotonic : Time::Instant do
    def limit(other : self) : self
      KeyExpiry.new({wall, other.wall}.min, {monotonic, other.monotonic}.min)
    end
  end

  # :nodoc:
  record AuthenticatedKeys, keys : Array(Crypto::Key), checked_at : Time, expiry : KeyExpiry

  # :nodoc:
  class KeyCache
    private MAX_ZONES = 256

    @entries = {} of Wire::Name => AuthenticatedKeys
    @lock = Mutex.new

    def lookup(zone : Wire::Name, now : Time) : AuthenticatedKeys?
      @lock.synchronize do
        next unless entry = @entries[zone]?
        if Time.instant >= entry.expiry.monotonic
          @entries.delete(zone)
          next
        end
        entry if entry.checked_at <= now && now < entry.expiry.wall
      end
    end

    def store(zone : Wire::Name, entry : AuthenticatedKeys) : Nil
      @lock.synchronize do
        next if entry.expiry.wall <= entry.checked_at || Time.instant >= entry.expiry.monotonic
        @entries.delete(zone)
        @entries.shift if @entries.size >= MAX_ZONES
        @entries[zone] = entry
      end
    end
  end
end

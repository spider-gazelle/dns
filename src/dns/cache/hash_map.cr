require "../cache"

class DNS::Cache::HashMap
  include Cache

  private record Entry, expires : Time::Instant, records : Array(DNS::Packet::ResourceRecord), additional : Bool
  private record NegativeEntry, expires : Time::Instant, extended_errors : Array(DNS::Packet::EDNS::ExtendedError)

  @lock : Mutex = Mutex.new
  @close : Channel(Nil) = Channel(Nil).new
  @negative = {} of String => Hash(UInt16?, NegativeEntry)

  def initialize
    @cache = Hash(String, Hash(UInt16, Entry)).new do |hash, domain|
      hash[domain] = Hash(UInt16, Entry).new
    end
    spawn { cleanup_loop }
  end

  def close : Nil
    @close.close
  end

  protected def cleanup_loop
    loop do
      interval = 4.minutes + rand(60).seconds

      select
      when @close.receive?
        break
      when timeout(interval)
        begin
          cleanup
        rescue error
          Log.error(exception: error) { "performing cache cleanup" }
        end
      end
    end
  end

  # check for a cached record
  def lookup(domain : String, query : UInt16) : DNS::Packet::ResourceRecord?
    lookup_all(domain, query).try(&.first?)
  end

  def lookup_all(domain : String, query : UInt16) : Array(DNS::Packet::ResourceRecord)?
    @lock.synchronize do
      return unless (domain_cache = @cache[domain]?) && (entry = domain_cache[query]?)
      return entry.records.dup if Time.instant < entry.expires

      domain_cache.delete(query)
      @cache.delete(domain) if domain_cache.empty?
    end
    nil
  end

  def lookup_negative(domain : String, query : UInt16) : Cache::Negative?
    @lock.synchronize { active_negative(domain, query, Time.instant) }
  end

  private def active_negative(domain : String, query : UInt16, now : Time::Instant) : Cache::Negative?
    return unless entries = @negative[domain]?
    {nil, query}.each do |type|
      if entry = entries[type]?
        return Cache::Negative.new(type.nil?, entry.extended_errors.dup) if now < entry.expires
        entries.delete(type)
      end
    end
    @negative.delete(domain) if entries.empty?
    nil
  end

  def store_negative(domain : String, query : UInt16?, ttl : Time::Span, *, extended_errors = [] of DNS::Packet::EDNS::ExtendedError) : Nil
    return unless ttl > Time::Span.zero

    entry = NegativeEntry.new(Time.instant + ttl, extended_errors.dup)
    @lock.synchronize do
      if query
        entries = @negative[domain] ||= {} of UInt16? => NegativeEntry
        entries.delete(nil)
        entries[query] = entry
        @cache[domain]?.try(&.delete(query))
      else
        @negative[domain] = {nil.as(UInt16?) => entry}
        @cache.delete(domain)
      end
    end
  end

  # store a result in the cache
  def store(domain : String, result : DNS::Packet::ResourceRecord) : Nil
    store_rrset(domain, [result])
  end

  def store_rrset(domain : String, records : Array(DNS::Packet::ResourceRecord), *, additional : Bool = false) : Nil
    return unless record = records.first?
    return if record.type == DNS::RecordType::OPT.value
    ttl = records.min_of(&.ttl)
    now = Time.instant
    @lock.synchronize do
      return if additional && prefer_cached_answer?(domain, record.type, now)

      invalidate_negative(domain, record.type) unless additional

      if ttl > Time::Span.zero
        @cache[domain][record.type] = Entry.new(now + ttl, records.dup, additional)
      elsif domain_cache = @cache[domain]?
        domain_cache.delete(record.type)
        @cache.delete(domain) if domain_cache.empty?
      end
    end
  end

  private def prefer_cached_answer?(domain : String, query : UInt16, now : Time::Instant) : Bool
    if entry = @cache[domain]?.try(&.[query]?)
      return true if !entry.additional && now < entry.expires
    end
    !active_negative(domain, query, now).nil?
  end

  private def invalidate_negative(domain : String, query : UInt16) : Nil
    return unless entries = @negative[domain]?
    entries.delete(nil)
    entries.delete(query)
    @negative.delete(domain) if entries.empty?
  end

  # cleanup any expired entries
  def cleanup : Nil
    now = Time.instant

    @lock.synchronize do
      @cache.reject! do |_domain, records|
        records.reject! do |_query, entry|
          now >= entry.expires
        end
        records.empty?
      end
      @negative.reject! do |_domain, entries|
        entries.reject! { |_, entry| now >= entry.expires }
        entries.empty?
      end
    end
  end

  def clear : Nil
    @lock.synchronize do
      @cache.clear
      @negative.clear
    end
  end
end

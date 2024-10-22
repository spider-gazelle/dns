require "../cache"

class DNS::SimpleCache
  include Cache

  @lock : Mutex = Mutex.new

  def initialize
    @cache = Hash(String, Hash(UInt16, Tuple(Time, DNS::ResourceRecord))).new do |hash, domain|
      hash[domain] = Hash(UInt16, Tuple(Time, DNS::ResourceRecord)).new
    end
  end

  # check for a cached record
  def lookup(domain : String, query : UInt16) : DNS::ResourceRecord?
    @lock.synchronize do
      if domain_cache = @cache[domain]?
        if entry = domain_cache[query]?
          expiry_time, record = entry
          if Time.utc < expiry_time
            return record
          else
            # Entry expired
            domain_cache.delete(query)
          end
        end
      end
    end
    nil
  end

  # store a result in the cache
  def store(domain : String, result : DNS::ResourceRecord)
    expiry_time = result.ttl.seconds.from_now
    @lock.synchronize { @cache[domain][result.type] = {expiry_time, result} }
  end

  # cleanup any expired entries
  def cleanup : Nil
    now = Time.utc

    @lock.synchronize do
      @cache.reject! do |_domain, records|
        records.reject! do |_query, (expiry_time, _result)|
          now >= expiry_time
        end
        records.empty?
      end
    end
  end
end

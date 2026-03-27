{% if flag?(:windows) %}
  require "./servers/windows"
{% elsif flag?(:darwin) %}
  require "./servers/darwin"
{% else %}
  require "./servers/unix"
{% end %}

# System-defined DNS servers and search domain configuration
class DNS::Servers
  class_property fallback : Array(String) { ["1.1.1.1", "8.8.8.8"] }

  # Cached default instance loaded from host config
  class_getter host : DNS::Servers { DNS::Servers.new }

  # Instance properties
  property servers : Array(String)
  property search : Array(String)
  property ndots : Int32

  # Load from system configuration (platform-specific)
  def initialize
    @servers, @search, @ndots = DNS::Servers.load_system_config
  end

  # Manual configuration
  def initialize(@servers : Array(String), @search : Array(String) = [] of String, @ndots : Int32 = 1)
  end

  # Clear cached host configuration to force reload
  def self.reload
    @@host = nil
  end

  # Instance expand method using instance settings
  def expand(name : String) : Array(String)
    DNS::Servers.expand(name, search: @search, ndots: @ndots)
  end

  # Expand a domain name according to resolv.conf search logic
  #
  # Returns an ordered list of domain names to try based on:
  # - FQDN detection (trailing dot)
  # - ndots threshold (if dots in name >= ndots, try bare name first)
  # - Search domain suffixes
  #
  # Example behaviors:
  # - "redis" with search=["svc.cluster.local"], ndots=1 → ["redis.svc.cluster.local", "redis"]
  # - "api.svc" with search=["svc.cluster.local"], ndots=1 → ["api.svc", "api.svc.cluster.local"]
  # - "www.google.com." (FQDN) → ["www.google.com"]
  def self.expand(name : String, *, search : Array(String) = host.search, ndots : Int32 = host.ndots) : Array(String)
    # FQDN with trailing dot - return as-is without the dot
    if name.ends_with?('.')
      return [name.rchop]
    end

    # Count dots in the name
    dot_count = name.count('.')

    # Build candidates list
    candidates = [] of String

    # Generate search domain candidates
    search_candidates = [] of String
    search.each do |suffix|
      # Avoid overlap: if name already ends with part of the search domain, skip
      # e.g., "redis.svc" + "svc.cluster.local" should not become "redis.svc.svc.cluster.local"
      unless overlaps_suffix?(name, suffix)
        search_candidates << "#{name}.#{suffix}"
      end
    end

    # Apply ndots logic:
    # If dot_count >= ndots, the name is considered "qualified enough" to try first
    # Otherwise, try search domains first
    if dot_count >= ndots
      # Name has enough dots - try it first, then search domains
      candidates << name
      candidates.concat(search_candidates)
    else
      # Name doesn't have enough dots - try search domains first, then bare name
      candidates.concat(search_candidates)
      candidates << name
    end

    # Deduplicate while preserving order
    candidates.uniq
  end

  # Check if name already ends with a prefix of the search suffix
  # to avoid duplicate segments like "redis.svc.svc.cluster.local"
  private def self.overlaps_suffix?(name : String, suffix : String) : Bool
    suffix_parts = suffix.split('.')
    name_lower = name.downcase

    # Check if name ends with any prefix of the suffix
    # e.g., for suffix "svc.cluster.local", check:
    # - ends with "svc.cluster.local"
    # - ends with "svc.cluster"
    # - ends with "svc"
    suffix_parts.size.times do |i|
      partial = suffix_parts[0..i].join('.')
      if name_lower.ends_with?(".#{partial.downcase}") || name_lower == partial.downcase
        return true
      end
    end

    false
  end
end

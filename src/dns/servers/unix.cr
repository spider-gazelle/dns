class DNS::Servers
  class_property resolv_conf : String = "/etc/resolv.conf"

  # Load DNS configuration from /etc/resolv.conf
  # Returns: {servers, search_domains, ndots, timeout, attempts}
  protected def self.load_system_config : Tuple(Array(String), Array(String), Int32, Time::Span, Int32)
    servers = [] of String
    search = [] of String
    domain : String? = nil
    ndots = 1                   # default per resolv.conf(5)
    timeout = DNS.timeout       # base per-try timeout
    attempts = DEFAULT_ATTEMPTS # whole-list query passes

    File.open(resolv_conf) do |file|
      file.each_line do |line|
        # Strip comments
        line = line.split('#', 2).first.strip

        case line
        when /^\s*nameserver\s+(.+)/
          # nameserver IP - DNS server address
          servers << $1.strip
        when /^\s*search\s+(.+)/
          # search domain1 domain2 ... - search list
          search = $1.split.map(&.strip).reject(&.empty?)
        when /^\s*domain\s+(.+)/
          # domain name - local domain name (fallback if no search)
          domain = $1.strip
        when /^\s*options\s+(.+)/
          # options opt1 opt2:value ...
          ndots, timeout, attempts = parse_options($1, ndots, timeout, attempts)
        end
      end
    end

    # If no search directive but domain was specified, use domain as search
    if search.empty? && domain
      search = [domain]
    end

    {servers, search, ndots, timeout, attempts}
  rescue ex
    Log.warn(exception: ex) { "failed to parse resolv.conf: #{resolv_conf}" }
    {[] of String, [] of String, 1, DNS.timeout, DEFAULT_ATTEMPTS}
  end

  # parse a resolv.conf `options` line, returning updated {ndots, timeout, attempts}
  protected def self.parse_options(line : String, ndots : Int32, timeout : Time::Span, attempts : Int32) : Tuple(Int32, Time::Span, Int32)
    line.split.each do |opt|
      key, _, value = opt.partition(':')
      number = value.to_i?
      next unless number

      case key
      when "ndots"    then ndots = number.clamp(0, 15)           # resolv.conf limits ndots to 0..15
      when "timeout"  then timeout = number.clamp(1, 30).seconds # glibc clamps timeout to <= 30s
      when "attempts" then attempts = number.clamp(1, 5)         # glibc clamps attempts to <= 5
      end
    end
    {ndots, timeout, attempts}
  end
end

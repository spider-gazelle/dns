class DNS::Servers
  class_property resolv_conf : String = "/etc/resolv.conf"

  # Load DNS configuration from /etc/resolv.conf
  # Returns: {servers, search_domains, ndots}
  protected def self.load_system_config : Tuple(Array(String), Array(String), Int32)
    servers = [] of String
    search = [] of String
    domain : String? = nil
    ndots = 1 # default per resolv.conf(5)

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
          $1.split.each do |opt|
            if opt.starts_with?("ndots:")
              if value = opt.split(':', 2)[1]?.try(&.to_i?)
                ndots = value.clamp(1, 15) # resolv.conf limits ndots to 15
              end
            end
          end
        end
      end
    end

    # If no search directive but domain was specified, use domain as search
    if search.empty? && domain
      search = [domain]
    end

    {servers, search, ndots}
  rescue ex
    Log.warn(exception: ex) { "failed to parse resolv.conf: #{resolv_conf}" }
    {[] of String, [] of String, 1}
  end
end

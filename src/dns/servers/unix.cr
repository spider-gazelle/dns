module DNS::Servers
  class_property resolv_conf : String = "/etc/resolv.conf"

  class_getter from_host : Array(String) do
    dns_servers = [] of String
    File.open(resolv_conf) do |file|
      file.each_line do |line|
        if line =~ /^\s*nameserver\s+([^\s]+)/
          dns_servers << $1
        end
      end
    end
    dns_servers
  rescue ex
    Log.warn(exception: ex) { "failed to parse resolv.conf: #{resolv_conf}" }
    [] of String
  end
end

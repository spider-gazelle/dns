module DNS::Hosts
  {% if flag?(:windows) %}
    class_property hosts_file : String = File.join(ENV["SystemRoot"] || ENV["windir"] || "C:\\WINDOWS", "System32", "drivers", "etc", "hosts")
  {% else %}
    class_property hosts_file : String = "/etc/hosts"
  {% end %}

  # a parser for both unix and windows hosts files
  def self.parse_hosts_file(path : String = hosts_file)
    # put in some sane defaults in case we can't parse the file for some reason
    # also windows assumes these addresses, they don't have to be in the hosts file
    hosts = {
      Resource::A::RECORD_TYPE => Hash(String, String){
        "localhost" => "127.0.0.1",
      },
      Resource::AAAA::RECORD_TYPE => Hash(String, String){
        "localhost" => "::1",
      },
    }

    begin
      File.each_line(path) do |line|
        # Remove comments and leading/trailing whitespace
        line = line.gsub(/#.*/, "").strip

        # Skip empty lines
        next if line.empty?

        # Split the line into IP and hostnames
        parts = line.split(/\s+/)
        ip = parts.shift

        # Map each hostname to the IP address
        if Socket::IPAddress.valid?(ip)
          ip_address = Socket::IPAddress.new(ip, 0)
          family = case ip_address.family
                   when .inet?
                     hosts[Resource::A::RECORD_TYPE]
                   when .inet6?
                     hosts[Resource::AAAA::RECORD_TYPE]
                   else
                     raise NotImplementedError.new("unreachable")
                   end

          parts.each do |hostname|
            family[URI::Punycode.to_ascii(hostname.downcase)] = ip
          end
        end
      end
    rescue ex
      Log.warn(exception: ex) { "failed to parse hosts file: #{path}" }
    end

    hosts
  end

  class_getter hosts : Hash(UInt16, Hash(String, String)) { parse_hosts_file }

  def self.lookup(domain : String, record : UInt16) : DNS::Packet::ResourceRecord?
    return nil unless {Resource::A::RECORD_TYPE, Resource::AAAA::RECORD_TYPE}.includes?(record)

    if ip = hosts[record][domain]?
      resource = case record
                 when Resource::A::RECORD_TYPE
                   Resource::A.new(ip)
                 when Resource::AAAA::RECORD_TYPE
                   Resource::AAAA.new(ip)
                 else
                   return nil
                 end

      Packet::ResourceRecord.new(domain, record, ClassCode::Internet.value, 0.seconds, resource)
    end
  end
end

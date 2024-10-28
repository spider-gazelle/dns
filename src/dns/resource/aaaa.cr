module DNS
  struct Resource::AAAA
    include Resource

    RECORD_TYPE = 28_u16

    getter address : String

    def initialize(@address)
    end

    def initialize(resource_data : Bytes, message : Bytes)
      @address = resource_data.each_slice(2).map { |bytes|
        ((bytes[0].to_u16 << 8) | bytes[1].to_u16).to_s(16)
      }.join(":")
    end

    def to_ip(port = 0) : Socket::IPAddress
      Socket::IPAddress.new(address, port)
    end

    def self.expand_ipv6(ip : Socket::IPAddress) : String
      parts = ip.address.split("::")

      if parts.size == 1
        # No '::' present
        groups = parts[0].split(":")
      else
        # '::' is present
        left, right = parts
        left_groups = left.empty? ? [] of String : left.split(":")
        right_groups = right.empty? ? [] of String : right.split(":")
        total_groups = left_groups.size + right_groups.size
        zeros = Array.new(8 - total_groups, "0000")
        groups = left_groups + zeros + right_groups
      end

      groups.map(&.rjust(4, '0')).join(':')
    end
  end
end

module DNS
  struct Resource::A
    include Resource

    RECORD_TYPE = 1_u16

    getter address : String

    def initialize(@address)
    end

    def initialize(resource_data : Bytes, message : Bytes)
      @address = resource_data.map(&.to_s).join(".")
    end

    def to_ip(port = 0) : Socket::IPAddress
      Socket::IPAddress.new(address, port)
    end
  end
end

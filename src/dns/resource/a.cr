module DNS
  struct Resource::A < Resource
    getter address : String

    def initialize(resource_data : Bytes, message : Bytes)
      @address = resource_data.map(&.to_s).join(".")
    end

    def to_ip(port = 0) : Socket::IPAddress
      Socket::IPAddress.new(address, port)
    end
  end

  Resource.register_record(RecordType::A, Resource::A)
end

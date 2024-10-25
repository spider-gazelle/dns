module DNS
  # NS record parsing
  struct Resource::NS
    include Resource

    RECORD_TYPE = 2_u16

    getter name_server : String

    def initialize(resource_data : Bytes, message : Bytes)
      # NS records contain a single domain name, which represents the name server.
      @name_server = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end
end

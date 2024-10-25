module DNS
  # PTR record parsing
  struct Resource::PTR
    include Resource

    RECORD_TYPE = 12_u16

    getter domain_name : String

    def initialize(resource_data : Bytes, message : Bytes)
      # PTR records contain a single domain name, which is the target of the reverse DNS lookup.
      @domain_name = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end
end

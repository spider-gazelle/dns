module DNS
  # PTR record parsing
  struct Resource::PTR < Resource
    getter domain_name : String

    def initialize(resource_data : Bytes, message : Bytes)
      # PTR records contain a single domain name, which is the target of the reverse DNS lookup.
      @domain_name = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end

  Resource.register_record(RecordCode::PTR, Resource::PTR)
end

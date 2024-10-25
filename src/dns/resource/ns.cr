module DNS
  # NS record parsing
  struct Resource::NS < Resource
    getter name_server : String

    def initialize(resource_data : Bytes, message : Bytes)
      # NS records contain a single domain name, which represents the name server.
      @name_server = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end

  Resource.register_record(RecordType::NS, Resource::NS)
end

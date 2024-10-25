module DNS
  # CNAME record parsing
  struct Resource::CNAME < Resource
    getter target : String

    def initialize(resource_data : Bytes, message : Bytes)
      # The CNAME record contains a single domain name, so we parse it using the label-reading method.
      @target = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end

  Resource.register_record(RecordType::CNAME, Resource::CNAME)
end

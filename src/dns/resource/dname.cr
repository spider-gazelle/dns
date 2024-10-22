module DNS
  # DNAME record parsing
  struct Resource::DNAME < Resource
    getter target : String

    def initialize(resource_data : Bytes, message : Bytes)
      # The DNAME record contains a single domain name, so we parse it using the label-reading method.
      @target = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end

  Resource.register_record(RecordCode::DNAME, Resource::DNAME)
end

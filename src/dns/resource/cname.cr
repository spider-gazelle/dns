module DNS
  # CNAME record parsing
  struct Resource::CNAME
    include Resource

    RECORD_TYPE = 5_u16

    getter target : String

    def initialize(resource_data : Bytes, message : Bytes)
      # The CNAME record contains a single domain name, so we parse it using the label-reading method.
      @target = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end
end

module DNS
  # Delegation Name record, aliases an entire subtree of the domain name space to another domain
  struct Resource::DNAME
    include Resource

    RECORD_TYPE = 39_u16

    getter target : String

    def initialize(resource_data : Bytes, message : Bytes)
      # The DNAME record contains a single domain name, so we parse it using the label-reading method.
      @target = Resource.read_labels(IO::Memory.new(resource_data), message)
    end
  end
end

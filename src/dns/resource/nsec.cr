module DNS
  # DNSSEC proof of a name interval or absent record type (RFC 4034).
  struct Resource::NSEC
    include Resource

    RECORD_TYPE = 47_u16

    getter next_domain_labels : Array(String)
    getter types : Set(UInt16)

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @next_domain_labels = Resource.read_name_labels(io, message, allow_compression: false)
      @types = Resource.read_type_bitmap(io)
      raise IO::Error.new("empty NSEC type bitmap") if types.empty?
    end

    def next_domain : String
      next_domain_labels.join('.')
    end
  end
end

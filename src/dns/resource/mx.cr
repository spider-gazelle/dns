module DNS
  # MX record parsing
  struct Resource::MX
    include Resource

    RECORD_TYPE = 15_u16

    getter preference : UInt16
    getter exchange : String

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)

      # MX records start with a 16-bit preference value (priority)
      @preference = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Following the preference is the domain name of the mail exchange server
      @exchange = Resource.read_labels(io, message)
    end
  end
end

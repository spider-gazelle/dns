module DNS
  # SRV record parsing
  struct Resource::SRV
    include Resource

    RECORD_TYPE = 33_u16

    getter priority : UInt16 # Priority of the target host
    getter weight : UInt16   # Relative weight for records with the same priority
    getter port : UInt16     # Port on which the service is running
    getter target : String   # Target domain name of the service

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)

      # SRV records start with a 16-bit priority value
      @priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Followed by a 16-bit weight value
      @weight = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Then a 16-bit port value
      @port = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Finally, the target domain name
      @target = Resource.read_labels(io, message)
    end
  end
end

module DNS
  # SRV record parsing
  struct ResourceRecord::SRV < ResourceRecord::Payload
    getter priority : UInt16 # Priority of the target host
    getter weight : UInt16   # Relative weight for records with the same priority
    getter port : UInt16     # Port on which the service is running
    getter target : String   # Target domain name of the service

    def initialize(rdata : Bytes, message : Bytes)
      io = IO::Memory.new(rdata)

      # SRV records start with a 16-bit priority value
      @priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Followed by a 16-bit weight value
      @weight = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Then a 16-bit port value
      @port = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Finally, the target domain name
      @target = ResourceRecord::Payload.read_labels(io, message)
    end
  end

  ResourceRecord.register_record(RecordCode::SRV, ResourceRecord::SRV)
end

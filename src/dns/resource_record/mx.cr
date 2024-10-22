module DNS
  # MX record parsing
  struct ResourceRecord::MX < ResourceRecord::Payload
    getter preference : UInt16
    getter exchange : String

    def initialize(rdata : Bytes, message : Bytes)
      io = IO::Memory.new(rdata)

      # MX records start with a 16-bit preference value (priority)
      @preference = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

      # Following the preference is the domain name of the mail exchange server
      @exchange = ResourceRecord::Payload.read_labels(io, message)
    end
  end

  ResourceRecord.register_record(RecordCode::MX, ResourceRecord::MX)
end

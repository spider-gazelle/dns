module DNS
  # URI service discovery (RFC 7553).
  struct Resource::URI
    include Resource

    RECORD_TYPE = 256_u16

    getter priority : UInt16
    getter weight : UInt16
    getter target : String

    def initialize(resource_data : Bytes, message : Bytes)
      raise IO::Error.new("missing URI target") if resource_data.size < 5
      io = IO::Memory.new(resource_data)
      @priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      @weight = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      @target = String.new(resource_data[io.pos..])
    end
  end
end

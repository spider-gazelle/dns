module DNS
  # CPU and operating system information (RFC 1035).
  struct Resource::HINFO
    include Resource

    RECORD_TYPE = 13_u16

    getter cpu : String
    getter os : String

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @cpu = io.read_string(io.read_bytes(UInt8))
      @os = io.read_string(io.read_bytes(UInt8))
      raise IO::Error.new("trailing data after HINFO operating system") unless io.pos == io.size
    end
  end
end

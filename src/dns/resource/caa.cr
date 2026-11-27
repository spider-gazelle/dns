module DNS
  # Certification Authority Authorization (RFC 8659).
  struct Resource::CAA
    include Resource

    RECORD_TYPE = 257_u16

    getter flags : UInt8
    getter tag : String
    getter value : String

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @flags = io.read_bytes(UInt8)
      @tag = io.read_string(io.read_bytes(UInt8))
      if tag.empty? || !tag.each_byte.all?(&.chr.ascii_alphanumeric?)
        raise IO::Error.new("invalid CAA property tag")
      end
      @value = String.new(resource_data[io.pos..])
    end

    def issuer_critical? : Bool
      flags.bits_set?(0x80_u8)
    end
  end
end

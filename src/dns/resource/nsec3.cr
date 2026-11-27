module DNS
  # DNSSEC proof using hashed owner names (RFC 5155).
  struct Resource::NSEC3
    include Resource

    RECORD_TYPE = 50_u16

    getter hash_algorithm : UInt8
    getter flags : UInt8
    getter iterations : UInt16
    getter salt : Bytes
    getter next_hash : Bytes
    getter types : Set(UInt16)

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @hash_algorithm, @flags, @iterations, @salt = Resource.read_nsec3_parameters(io)
      @next_hash = Bytes.new(io.read_bytes(UInt8))
      io.read_fully(@next_hash)
      @types = Resource.read_type_bitmap(io)
    end

    def opt_out? : Bool
      flags.bits_set?(0x01_u8)
    end
  end
end

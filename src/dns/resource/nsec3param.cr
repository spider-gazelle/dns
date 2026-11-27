module DNS
  # NSEC3 parameters published at a zone apex (RFC 5155).
  struct Resource::NSEC3PARAM
    include Resource

    RECORD_TYPE = 51_u16

    getter hash_algorithm : UInt8
    getter flags : UInt8
    getter iterations : UInt16
    getter salt : Bytes

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @hash_algorithm, @flags, @iterations, @salt = Resource.read_nsec3_parameters(io)
      raise IO::Error.new("trailing data after NSEC3PARAM salt") unless io.pos == io.size
    end
  end
end

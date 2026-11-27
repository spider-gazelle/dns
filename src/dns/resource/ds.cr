module DNS
  # DNSSEC Delegation Signer (RFC 4034).
  struct Resource::DS
    include Resource

    RECORD_TYPE = 43_u16

    getter key_tag : UInt16
    getter algorithm : UInt8
    getter digest_type : UInt8
    getter digest : Bytes

    def initialize(resource_data : Bytes, message : Bytes)
      raise IO::Error.new("missing DS digest") if resource_data.size < 5
      @key_tag = IO::ByteFormat::BigEndian.decode(UInt16, resource_data[0, 2])
      @algorithm = resource_data[2]
      @digest_type = resource_data[3]
      @digest = resource_data[4..]
    end

    def initialize(@key_tag : UInt16, @algorithm : UInt8, @digest_type : UInt8, @digest : Bytes)
    end
  end
end

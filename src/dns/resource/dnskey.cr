module DNS
  # DNSSEC public key (RFC 4034).
  struct Resource::DNSKEY
    include Resource

    RECORD_TYPE = 48_u16

    getter flags : UInt16
    getter protocol : UInt8
    getter algorithm : UInt8
    getter public_key : Bytes
    getter key_tag : UInt16

    # :nodoc:
    getter wire_data : Bytes

    def initialize(resource_data : Bytes, message : Bytes)
      raise IO::Error.new("missing DNSKEY public key") if resource_data.size < 5
      @flags = IO::ByteFormat::BigEndian.decode(UInt16, resource_data[0, 2])
      @protocol = resource_data[2]
      @algorithm = resource_data[3]
      @public_key = resource_data[4..]
      @wire_data = resource_data
      @key_tag = calculate_tag
    end

    def zone_key? : Bool
      flags.bits_set?(0x0100_u16)
    end

    def revoked? : Bool
      flags.bits_set?(0x0080_u16)
    end

    def secure_entry_point? : Bool
      flags.bits_set?(0x0001_u16)
    end

    private def calculate_tag : UInt16
      if algorithm == 1
        raise IO::Error.new("short RSA/MD5 DNSKEY") if public_key.size < 3
        return (public_key[-3].to_u16 << 8) | public_key[-2].to_u16
      end

      checksum = 0_u32
      wire_data.each_with_index do |byte, index|
        checksum += index.even? ? byte.to_u32 << 8 : byte
      end
      ((checksum + (checksum >> 16)) & 0xffff).to_u16
    end
  end
end

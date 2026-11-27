module DNS
  # SSH host key fingerprint (RFC 4255).
  struct Resource::SSHFP
    include Resource

    RECORD_TYPE = 44_u16

    getter algorithm : UInt8
    getter fingerprint_type : UInt8
    getter fingerprint : Bytes

    def initialize(resource_data : Bytes, message : Bytes)
      raise IO::Error.new("missing SSHFP fingerprint") if resource_data.size < 3
      @algorithm = resource_data[0]
      @fingerprint_type = resource_data[1]
      @fingerprint = resource_data[2..]
    end
  end
end

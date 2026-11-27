module DNS
  # DANE TLS certificate association (RFC 6698).
  struct Resource::TLSA
    include Resource

    RECORD_TYPE = 52_u16

    getter certificate_usage : UInt8
    getter selector : UInt8
    getter matching_type : UInt8
    getter association_data : Bytes

    def initialize(resource_data : Bytes, message : Bytes)
      raise IO::Error.new("missing TLSA certificate association data") if resource_data.size < 4
      @certificate_usage = resource_data[0]
      @selector = resource_data[1]
      @matching_type = resource_data[2]
      @association_data = resource_data[3..]
    end
  end
end

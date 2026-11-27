module DNS
  # DNSSEC signature over a resource record set (RFC 4034).
  struct Resource::RRSIG
    include Resource

    RECORD_TYPE = 46_u16
    # :nodoc:
    HEADER_SIZE = 18

    getter type_covered : UInt16
    getter algorithm : UInt8
    getter labels : UInt8
    getter original_ttl : UInt32
    getter expiration : UInt32
    getter inception : UInt32
    getter key_tag : UInt16
    getter signer_labels : Array(String)
    getter signature : Bytes

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      format = IO::ByteFormat::BigEndian
      @type_covered = io.read_bytes(UInt16, format)
      @algorithm = io.read_bytes(UInt8)
      @labels = io.read_bytes(UInt8)
      @original_ttl = io.read_bytes(UInt32, format)
      @expiration = io.read_bytes(UInt32, format)
      @inception = io.read_bytes(UInt32, format)
      @key_tag = io.read_bytes(UInt16, format)
      @signer_labels = Resource.read_name_labels(io, message, allow_compression: false)
      @signature = resource_data[io.pos..]
      raise IO::Error.new("empty RRSIG signature") if signature.empty?
    end

    def signer_name : String
      signer_labels.join('.')
    end
  end
end

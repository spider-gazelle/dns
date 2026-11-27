module DNS
  # Naming Authority Pointer (RFC 3403).
  struct Resource::NAPTR
    include Resource

    RECORD_TYPE = 35_u16

    getter order : UInt16
    getter preference : UInt16
    getter flags : String
    getter service : String
    getter regexp : String
    getter replacement_labels : Array(String)

    # :nodoc:
    getter replacement_offset : Int32

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @order = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      @preference = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      @flags = io.read_string(io.read_bytes(UInt8))
      raise IO::Error.new("invalid NAPTR flags") unless flags.each_byte.all?(&.chr.ascii_alphanumeric?)
      @service = io.read_string(io.read_bytes(UInt8))
      @regexp = io.read_string(io.read_bytes(UInt8))
      @replacement_offset = io.pos.to_i
      @replacement_labels = Resource.read_name_labels(io, message, allow_compression: false)
      raise IO::Error.new("trailing data after NAPTR replacement") unless io.pos == io.size
      if !regexp.empty? && !replacement_labels.empty?
        raise IO::Error.new("NAPTR contains both a regular expression and a replacement")
      end
    end

    def replacement : String
      replacement_labels.join('.')
    end
  end
end

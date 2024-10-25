module DNS
  # HTTPS record parsing
  struct Resource::HTTPS
    include Resource

    RECORD_TYPE = 65_u16

    getter priority : UInt16
    getter target_name : String
    getter alpn : Array(String)
    getter svcparam : Hash(UInt16, Bytes)

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      @target_name = Resource.read_labels(io, message)

      @svcparam = {} of UInt16 => Bytes
      @alpn = [] of String

      # Read SvcParams
      while io.pos != io.size
        key = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
        length = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
        value = Bytes.new(length)
        io.read(value)

        case key
        when 1 # alpn
          alpn_io = IO::Memory.new(value)
          while alpn_io.pos != alpn_io.size
            alpn_length = alpn_io.read_byte.as(UInt8)
            @alpn << alpn_io.read_string(alpn_length)
          end
        else
          @svcparam[key] = value
        end
      end
    end
  end
end

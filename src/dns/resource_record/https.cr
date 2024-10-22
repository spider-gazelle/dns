module DNS
  # HTTPS record parsing
  struct ResourceRecord::HTTPS < ResourceRecord::Payload
    getter priority : UInt16
    getter target_name : String
    getter alpn : Array(String)
    getter svcparam : Hash(UInt16, Bytes)

    def initialize(rdata : Bytes, message : Bytes)
      io = IO::Memory.new(rdata)
      @priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      @target_name = ResourceRecord::Payload.read_labels(io, message)

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

  ResourceRecord.register_record(RecordCode::HTTPS, ResourceRecord::HTTPS)
end

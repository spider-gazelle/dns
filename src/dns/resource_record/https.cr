module DNS
  # HTTPS record parsing
  ResourceRecord.register_parser(RecordCode::HTTPS) do |rdata, message|
    io = IO::Memory.new(rdata)
    data = ResourceRecord::ParsedData.new

    priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    data["priority"] = priority.to_s

    target_name = ResourceRecord.read_labels(io, message)
    data["target_name"] = target_name

    # Read SvcParams
    while io.pos != io.size
      key = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      length = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      value = Bytes.new(length)
      io.read(value)

      case key
      when 1 # alpn
        alpn_protocols = [] of String
        alpn_io = IO::Memory.new(value)
        while alpn_io.pos != alpn_io.size
          alpn_length = alpn_io.read_byte.as(UInt8)
          alpn_protocols << alpn_io.read_string(alpn_length)
        end
        data["alpn"] = alpn_protocols.join(",")
      else
        data["svcparam_#{key}"] = value.hexstring
      end
    end

    data
  end
end

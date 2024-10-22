module DNS
  # TXT record parsing
  struct ResourceRecord::TXT < ResourceRecord::Payload
    getter text_data : Array(String) # Array of strings as multiple TXT records can exist

    def initialize(rdata : Bytes, message : Bytes)
      io = IO::Memory.new(rdata)
      @text_data = [] of String

      # TXT records can have one or more strings, each prefixed by a length byte
      while io.pos < io.size
        length = io.read_byte
        @text_data << io.read_string(length) if length
      end
    end
  end

  ResourceRecord.register_record(RecordCode::TXT, ResourceRecord::TXT)
end

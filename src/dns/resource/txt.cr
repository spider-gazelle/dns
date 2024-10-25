module DNS
  # TXT record parsing
  struct Resource::TXT
    include Resource

    RECORD_TYPE = 16_u16

    getter text_data : Array(String) # Array of strings as multiple TXT records can exist

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)
      @text_data = [] of String

      # TXT records can have one or more strings, each prefixed by a length byte
      while io.pos < io.size
        length = io.read_byte
        @text_data << io.read_string(length) if length
      end
    end
  end
end

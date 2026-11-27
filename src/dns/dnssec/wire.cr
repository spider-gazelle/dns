module DNS::DNSSEC
  # :nodoc:
  module Wire
    FORMAT = IO::ByteFormat::BigEndian
    IN     = ClassCode::Internet.value

    struct Name
      include Comparable(Name)

      getter labels : Array(String)

      def initialize(labels : Array(String))
        @labels = labels.map do |label|
          String.build(label.bytesize) do |part|
            label.each_byte { |byte| part.write_byte(byte.in?(65..90) ? byte + 32_u8 : byte) }
          end
        end
      end

      def self.from_text(text : String) : self
        text = URI::Punycode.to_ascii(text.rchop('.').downcase)
        labels = text.empty? ? [] of String : text.split('.')
        if text.bytesize > 253 || labels.any? { |label| label.empty? || label.bytesize > 63 }
          raise ArgumentError.new("invalid DNS name length")
        end
        new(labels)
      end

      def self.read(io : IO::Memory, message : Bytes, *, compression : Bool = true) : self
        new(Resource.read_name_labels(io, message, allow_compression: compression))
      end

      def wire(io : IO) : Nil
        labels.each do |label|
          io.write_byte(label.bytesize.to_u8)
          io.write(label.to_slice)
        end
        io.write_byte(0_u8)
      end

      def within?(zone : Name) : Bool
        size >= zone.size && labels.last(zone.size) == zone.labels
      end

      def size : Int32
        labels.size
      end

      def suffix(count : Int32) : Name
        Name.new(labels.last(count))
      end

      def wildcard : Name
        Name.new(["*"] + labels)
      end

      def to_s(io : IO) : Nil
        labels.join(io, '.')
        io << '.'
      end

      def query_text : String
        if labels.any? { |label| !label.ascii_only? || label.includes?('.') || label.includes?('\0') }
          raise ValidationError.new(Status::Indeterminate, "name cannot be expressed by the query API")
        end
        to_s
      end

      def <=>(other : Name) : Int32
        1.upto({size, other.size}.min) do |index|
          order = labels[-index] <=> other.labels[-index]
          return order unless order.zero?
        end
        size <=> other.size
      end

      def_equals_and_hash labels
    end

    record Question, name : Name, type : UInt16, class_code : UInt16

    record RR, name : Name, type : UInt16, class_code : UInt16, ttl : UInt32, data : Bytes do
      def public_record(ttl_limit : UInt32) : Packet::ResourceRecord
        io = IO::Memory.new
        name.wire(io)
        io.write_bytes(type, FORMAT)
        io.write_bytes(class_code, FORMAT)
        io.write_bytes({ttl, ttl_limit}.min, FORMAT)
        io.write_bytes(data.size.to_u16, FORMAT)
        io.write(data)
        Packet::ResourceRecord.from_slice(io.to_slice)
      end
    end

    struct Message
      getter question : Question
      getter answers : Array(RR)
      getter authorities : Array(RR)
      getter code : UInt16

      def initialize(packet : Packet)
        raise IO::Error.new("incomplete DNS reply") if !packet.response? || !packet.operation_code.zero? || packet.truncation?
        bytes = packet.wire_bytes || packet.to_slice
        raise IO::Error.new("oversized DNS reply") if bytes.size > UInt16::MAX
        io = IO::Memory.new(bytes)
        io.skip(4)
        count = io.read_bytes(UInt16, FORMAT)
        raise IO::Error.new("expected one DNS question in reply") unless count == 1
        answer_count = io.read_bytes(UInt16, FORMAT)
        authority_count = io.read_bytes(UInt16, FORMAT)
        io.skip(2)
        @question = Question.new(Name.read(io, bytes), io.read_bytes(UInt16, FORMAT), io.read_bytes(UInt16, FORMAT))
        @answers = read_records(io, bytes, answer_count)
        @authorities = read_records(io, bytes, authority_count)
        @code = packet.effective_response_code
      end

      def answer(name : Name, type : UInt16) : Array(RR)
        answers.select { |record| record.name == name && record.type == type }
      end

      private def read_records(io : IO::Memory, message : Bytes, count : UInt16) : Array(RR)
        records = [] of RR
        count.times do
          name = Name.read(io, message)
          type = io.read_bytes(UInt16, FORMAT)
          klass = io.read_bytes(UInt16, FORMAT)
          ttl = io.read_bytes(UInt32, FORMAT)
          length = io.read_bytes(UInt16, FORMAT)
          data = Bytes.new(length)
          io.read_fully(data)
          records << RR.new(name, type, klass, ttl, Wire.canonical_data(type, data, message)) if klass == IN
        end
        records
      end
    end

    def self.canonical_data(type : UInt16, data : Bytes, message : Bytes) : Bytes
      case type
      when 2, 3, 4, 5, 7, 8, 9, 12 then canonical_names(data, message, 0, 1)
      when 6, 14, 17               then canonical_names(data, message, 0, 2)
      when 15, 18, 21, 36          then canonical_names(data, message, 2, 1)
      when 26                      then canonical_names(data, message, 2, 2)
      when 24, 46                  then canonical_names(data, message, 18, 1, compression: false)
      when 33                      then canonical_names(data, message, 6, 1, compression: false)
      when 30                      then canonical_names(data, message, 0, 1)
      when 39                      then canonical_names(data, message, 0, 1, compression: false)
      when 35                      then naptr(data, message)
      when 38                      then a6(data, message)
      else                              data # Includes NSEC and SVCB/HTTPS, whose RDATA is retained as sent.
      end
    end

    private def self.canonical_names(data : Bytes, message : Bytes, prefix : Int32, names : Int32, *, compression : Bool = true) : Bytes
      raise IO::EOFError.new if prefix > data.size
      input = IO::Memory.new(data)
      output = IO::Memory.new
      output.write(data[0, prefix])
      input.pos = prefix
      names.times { Name.read(input, message, compression: compression).wire(output) }
      output.write(data[input.pos..])
      output.to_slice
    end

    private def self.naptr(data : Bytes, message : Bytes) : Bytes
      input = IO::Memory.new(data)
      input.skip(4)
      3.times { input.skip(input.read_byte || raise IO::EOFError.new) }
      canonical_names(data, message, input.pos.to_i, 1, compression: false)
    end

    private def self.a6(data : Bytes, message : Bytes) : Bytes
      raise IO::EOFError.new if data.empty?
      prefix = data[0].to_i
      raise IO::Error.new("invalid A6 prefix") if prefix > 128
      return data if prefix.zero?
      canonical_names(data, message, 1 + (128 - prefix + 7) // 8, 1, compression: false)
    end
  end
end

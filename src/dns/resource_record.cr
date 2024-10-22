struct DNS::ResourceRecord
  property name : String
  property type : UInt16
  property class_code : UInt16
  property ttl : UInt32
  property rdlength : UInt16
  property rdata : Bytes

  alias ParsedData = Hash(String, String | Bool | Int64 | Float64)

  property parsed_data : ParsedData?

  @@parsers = Hash(UInt16, Proc(Bytes, Bytes, ParsedData?)).new

  def self.register_parser(type : UInt16 | RecordCode, &parser : Proc(Bytes, Bytes, ParsedData?))
    @@parsers[type.is_a?(RecordCode) ? type.value : type] = parser
  end

  def initialize(@name : String, @type : UInt16, @class_code : UInt16, @ttl : UInt32, @rdlength : UInt16, @rdata : Bytes, @data : ParsedData? = nil)
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_io(IO::Memory.new(bytes), format)
  end

  def self.from_io(io : IO::Memory, format : IO::ByteFormat = IO::ByteFormat::BigEndian) : self
    name = read_labels(io)
    type = io.read_bytes(UInt16, format)
    class_code = io.read_bytes(UInt16, format)
    ttl = io.read_bytes(UInt32, format)
    rdlength = io.read_bytes(UInt16, format)
    rdata = Bytes.new(rdlength)
    io.read(rdata)

    parsed_data = parse_rdata(type, rdata, io.to_slice)

    new(name, type, class_code, ttl, rdlength, rdata, parsed_data)
  end

  def self.parse_rdata(type : UInt16, rdata : Bytes, message : Bytes) : ParsedData?
    if parser = @@parsers[type]?
      parser.call(rdata, message)
    else
      nil
    end
  end

  def self.read_labels(io : IO::Memory) : String
    read_labels(io, io.to_slice)
  end

  def self.read_labels(io : IO::Memory, message : Bytes) : String
    labels = [] of String
    loop do
      length = io.read_byte
      break if length.nil?
      break if length.zero?

      if length & 0xC0 == 0xC0
        # Pointer
        pointer = ((length & 0x3F) << 8) | io.read_byte.as(UInt8)
        labels << get_labels_from_pointer(pointer, message)
        break
      else
        labels << io.read_string(length)
      end
    end
    labels.join(".")
  end

  def self.get_labels_from_pointer(pointer : UInt16, message : Bytes) : String
    io = IO::Memory.new(message)
    io.pos = pointer
    read_labels(io, message)
  end

  def to_s : String
    data_str = data ? data.to_s : "Raw Data: #{rdata.hexstring}"
    "Name: #{name}, Type: #{type}, Class: #{class_code}, TTL: #{ttl}, Data: #{data_str}"
  end
end

require "./resource_record/*"

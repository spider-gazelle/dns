class DNS::Packet::Question
  property name : String
  property type : UInt16
  property class_code : UInt16 = 1 # IN class

  def initialize(@name : String, @type : UInt16, @class_code : UInt16 = 1_u16)
  end

  def initialize(@name : String, @type : UInt16, @class_code : UInt16 = 1_u16)
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_io(IO::Memory.new(bytes), format)
  end

  def self.from_io(io : IO::Memory, format : IO::ByteFormat = IO::ByteFormat::BigEndian) : self
    name = Resource.read_labels(io)
    type = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    class_code = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

    new(name, type, class_code)
  end

  def to_slice : Bytes
    io = IO::Memory.new
    to_io(io)
    io.to_slice
  end

  def to_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    name.split('.').each do |label|
      io.write_byte(label.size.to_u8)
      io.write(label.to_slice)
    end
    io.write_byte(0_u8) # Null terminator for the domain name
    io.write_bytes(type, IO::ByteFormat::BigEndian)
    io.write_bytes(class_code, IO::ByteFormat::BigEndian)
  end

  def self.build_query(domain : String, type : UInt16, id : UInt16, class_code : UInt16 = 1_u16) : Bytes
    DNS::Packet.new(
      id: id,
      questions: [DNS::Packet::Question.new(domain, type, class_code)]
    ).to_slice
  end
end

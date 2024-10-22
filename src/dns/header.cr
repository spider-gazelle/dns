class DNS::Header
  property id : UInt16
  property qr : UInt8 = 0
  property opcode : UInt8 = 0
  property aa : UInt8 = 0
  property tc : UInt8 = 0
  property rd : UInt8 = 1
  property ra : UInt8 = 0
  property z : UInt8 = 0
  property rcode : UInt8 = 0
  property qdcount : UInt16 = 1
  property ancount : UInt16 = 0
  property nscount : UInt16 = 0
  property arcount : UInt16 = 0

  def initialize(@id : UInt16)
  end

  def to_slice : Bytes
    io = IO::Memory.new
    io.write_bytes(id, IO::ByteFormat::BigEndian)
    io.write_byte((qr << 7) | (opcode << 3) | (aa << 2) | (tc << 1) | rd)
    io.write_byte((ra << 7) | (z << 4) | rcode)
    io.write_bytes(qdcount, IO::ByteFormat::BigEndian)
    io.write_bytes(ancount, IO::ByteFormat::BigEndian)
    io.write_bytes(nscount, IO::ByteFormat::BigEndian)
    io.write_bytes(arcount, IO::ByteFormat::BigEndian)
    io.to_slice
  end
end

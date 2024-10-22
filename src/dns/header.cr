class DNS::Header
  property id : UInt16
  property qr : UInt8 = 0     # query / response flag
  property opcode : UInt8 = 0 # operation code
  property aa : UInt8 = 0     # authoritative answer
  property tc : UInt8 = 0     # truncation
  property rd : UInt8 = 1     # recursion desired
  property ra : UInt8 = 0     # recursion available
  property z : UInt8 = 0      # Reserved
  property rcode : UInt8 = 0  # Response Code
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

class DNS::Question
  property qname : String
  property qtype : UInt16
  property qclass : UInt16 = 1 # IN class

  def initialize(@qname : String, @qtype : UInt16, @qclass : UInt16 = 1_u16)
  end

  def to_slice : Bytes
    io = IO::Memory.new
    qname.split('.').each do |label|
      io.write_byte(label.size.to_u8)
      io.write(label.to_slice)
    end
    io.write_byte(0_u8) # Null terminator for the domain name
    io.write_bytes(qtype, IO::ByteFormat::BigEndian)
    io.write_bytes(qclass, IO::ByteFormat::BigEndian)
    io.to_slice
  end
end

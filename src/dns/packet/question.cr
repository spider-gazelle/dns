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

  # Build a DNS query message.
  #
  # When *edns_udp_size* is non-zero an EDNS0 OPT pseudo-record (RFC 6891) is
  # appended advertising the given UDP payload size (DNS Flag Day 2020 recommends
  # 1232). Pass 0 to omit it (e.g. for mDNS).
  def self.build_query(domain : String, type : UInt16, id : UInt16, class_code : UInt16 = 1_u16, edns_udp_size : UInt16 = 0_u16) : Bytes
    additionals = [] of DNS::Packet::ResourceRecord
    if edns_udp_size > 0
      # OPT record: root name, type 41, CLASS field carries the advertised UDP
      # payload size, TTL field carries extended-rcode/version/flags (all 0, DO off)
      additionals << DNS::Packet::ResourceRecord.new("", 41_u16, edns_udp_size, 0.seconds)
    end

    DNS::Packet.new(
      id: id,
      questions: [DNS::Packet::Question.new(domain, type, class_code)],
      additionals: additionals,
    ).to_slice
  end
end

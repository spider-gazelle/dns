class DNS::Packet::Question
  property name : String
  property type : UInt16
  property class_code : UInt16 = 1 # IN class

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
    Resource.write_labels(io, name)
    io.write_bytes(type, IO::ByteFormat::BigEndian)
    io.write_bytes(class_code, IO::ByteFormat::BigEndian)
  end

  # Build a DNS query message.
  #
  # When *edns_udp_size* is non-zero an EDNS0 OPT pseudo-record (RFC 6891) is
  # appended advertising the given UDP payload size (DNS Flag Day 2020 recommends
  # 1232). Pass 0 to omit it (e.g. for mDNS).
  def self.build_query(
    domain : String,
    type : UInt16,
    id : UInt16,
    class_code : UInt16 = 1_u16,
    edns_udp_size : UInt16 = 0_u16,
    *,
    edns : EDNS? = nil,
    dnssec : DNSSEC::Options = DNSSEC::Options.new,
  ) : Bytes
    additionals = [] of DNS::Packet::ResourceRecord
    edns ||= EDNS.new(edns_udp_size) if edns_udp_size > 0
    edns = (edns || EDNS.new).with_dnssec_ok if dnssec.dnssec_ok?
    additionals << edns.to_resource_record if edns

    DNS::Packet.new(
      id: id,
      questions: [DNS::Packet::Question.new(domain, type, class_code)],
      additionals: additionals,
      authenticated_data: dnssec.request_ad?,
      checking_disabled: dnssec.checking_disabled?,
    ).to_slice
  end
end

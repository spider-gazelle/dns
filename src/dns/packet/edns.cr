# The OPT pseudo-record and its extensible option list.
struct DNS::Packet::EDNS
  DEFAULT_UDP_SIZE =   1232_u16
  DNSSEC_OK        = 0x8000_u16
  COOKIE           =     10_u16
  EXTENDED_ERROR   =     15_u16

  record Option, code : UInt16, data : Bytes
  record ExtendedError, code : UInt16, text : String?

  getter udp_payload_size : UInt16
  getter extended_rcode : UInt8
  getter version : UInt8
  getter flags : UInt16
  getter options : Array(Option)

  def initialize(
    @udp_payload_size : UInt16 = DEFAULT_UDP_SIZE,
    @options : Array(Option) = [] of Option,
    *,
    @extended_rcode : UInt8 = 0_u8,
    @version : UInt8 = 0_u8,
    @flags : UInt16 = 0_u16,
  )
  end

  def self.from_additionals(records : Array(ResourceRecord)) : self?
    opt : ResourceRecord? = nil
    records.each do |record|
      next unless record.type == RecordType::OPT.value
      raise IO::Error.new("invalid DNS OPT record") if opt || !record.name.empty?
      opt = record
    end
    return unless opt

    metadata = opt.ttl.total_seconds.to_u32
    io = IO::Memory.new(opt.resource_data)
    options = [] of Option
    until io.pos == io.size
      code = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      length = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      data = Bytes.new(length)
      io.read_fully(data)
      options << Option.new(code, data)
    end
    new(opt.class_code, options,
      extended_rcode: (metadata >> 24).to_u8,
      version: ((metadata >> 16) & 0xff).to_u8,
      flags: (metadata & 0xffff).to_u16)
  end

  def to_resource_record : ResourceRecord
    io = IO::Memory.new
    options.each do |option|
      io.write_bytes(option.code, IO::ByteFormat::BigEndian)
      io.write_bytes(option.data.size.to_u16, IO::ByteFormat::BigEndian)
      io.write(option.data)
    end
    metadata = (extended_rcode.to_u32 << 24) | (version.to_u32 << 16) | flags
    ResourceRecord.new("", RecordType::OPT.value, udp_payload_size, metadata.seconds, resource_data: io.to_slice)
  end

  def option(code : UInt16) : Option?
    options.find { |option| option.code == code }
  end

  def dnssec_ok? : Bool
    flags.bits_set?(DNSSEC_OK)
  end

  def with_dnssec_ok : self
    self.class.new(udp_payload_size, options, extended_rcode: extended_rcode, version: version, flags: flags | DNSSEC_OK)
  end

  def extended_errors : Array(ExtendedError)
    options.compact_map do |option|
      data = option.data
      next unless option.code == EXTENDED_ERROR && data.size >= 2

      code = IO::ByteFormat::BigEndian.decode(UInt16, data)
      text = String.new(data[2..]).scrub if data.size > 2
      ExtendedError.new(code, text)
    end
  end
end

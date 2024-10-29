require "../resource"

struct DNS::Packet::ResourceRecord
  property name : String
  property type : UInt16
  property class_code : UInt16
  property ttl : Time::Span
  property resource_data : Bytes

  getter resource : Resource?

  BLANK = Bytes.new(0)

  def initialize(@name : String, @type : UInt16, @class_code : UInt16, @ttl : Time::Span, @resource : Resource? = nil, @resource_data : Bytes = BLANK)
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_io(IO::Memory.new(bytes), format)
  end

  def self.from_io(io : IO::Memory, format : IO::ByteFormat = IO::ByteFormat::BigEndian) : self
    name = Resource.read_labels(io)
    type = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    class_code = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    ttl = io.read_bytes(UInt32, IO::ByteFormat::BigEndian).seconds
    rdlength = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    resource_data = Bytes.new(rdlength)
    io.read_fully(resource_data)

    resource = DNS::Resource::LOOKUP[type]?.try(&.new(resource_data, io.to_slice))
    new(name, type, class_code, ttl, resource, resource_data)
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
    io.write_bytes(ttl.total_seconds.to_u32, IO::ByteFormat::BigEndian)
    io.write_bytes(resource_data.size.to_u16, IO::ByteFormat::BigEndian)
    io.write(resource_data)
  end

  def to_s : String
    data_str = parsed_data ? parsed_data.to_s : "Raw Data: #{resource_data.hexstring}"
    "Name: #{name}, Type: #{type}, Class: #{class_code}, TTL: #{ttl}, Data: #{data_str}"
  end

  def record_type : RecordType
    RecordType.from_value type
  end

  # a helper for obtaining IP addresses
  def ip_address(port = 0) : Socket::IPAddress
    code = record_type
    case code
    when .a?
      resource.as(Resource::A).to_ip port
    when .aaaa?
      resource.as(Resource::AAAA).to_ip port
    else
      raise "record #{code} is not an IP Address"
    end
  end

  # a helper for obtaining a cname target
  def cname : String
    resource.as(Resource::CNAME).target
  end

  # a helper for obtaining a dname target
  def dname : String
    resource.as(Resource::DNAME).target
  end

  # a helper for obtaining a name server
  def name_server : String
    resource.as(Resource::NS).name_server
  end

  # a helper for obtaining TXT record data
  def text_data : String
    resource.as(Resource::TXT).text_data
  end
end

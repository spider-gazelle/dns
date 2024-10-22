struct DNS::ResourceRecord
  property name : String
  property type : UInt16
  property class_code : UInt16
  property ttl : UInt32
  property rdlength : UInt16
  property rdata : Bytes

  property payload : Payload?

  class_getter parsers = Hash(UInt16, Proc(Bytes, Bytes, Payload?)).new

  macro register_record(type, parser)
    {% if type.is_a?(Path) %}
      %type_code = {{type}}.value
    {% else %}
      %type_code = {{type}}
    {% end %}
    DNS::ResourceRecord.parsers[%type_code] = Proc(Bytes, Bytes, DNS::ResourceRecord::Payload?).new do |rdata, message|
      {{parser}}.new(rdata, message)
    end
  end

  def initialize(@name : String, @type : UInt16, @class_code : UInt16, @ttl : UInt32, @rdlength : UInt16, @rdata : Bytes, @payload : Payload? = nil)
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_io(IO::Memory.new(bytes), format)
  end

  def self.from_io(io : IO::Memory, format : IO::ByteFormat = IO::ByteFormat::BigEndian) : self
    name = Payload.read_labels(io)
    type = io.read_bytes(UInt16, format)
    class_code = io.read_bytes(UInt16, format)
    ttl = io.read_bytes(UInt32, format)
    rdlength = io.read_bytes(UInt16, format)
    rdata = Bytes.new(rdlength)
    io.read(rdata)

    parsed_data = parse_rdata(type, rdata, io.to_slice)

    new(name, type, class_code, ttl, rdlength, rdata, parsed_data)
  end

  def self.parse_rdata(type : UInt16, rdata : Bytes, message : Bytes) : Payload?
    if parser = @@parsers[type]?
      parser.call(rdata, message)
    else
      nil
    end
  end

  def to_s : String
    data_str = parsed_data ? parsed_data.to_s : "Raw Data: #{rdata.hexstring}"
    "Name: #{name}, Type: #{type}, Class: #{class_code}, TTL: #{ttl}, Data: #{data_str}"
  end
end

require "./resource_record/payload"
require "./resource_record/*"

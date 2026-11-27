require "./spec_helper"

describe DNS::Packet do
  it "round-trips root questions and absolute owner names" do
    question = DNS::Packet::Question.new(".", DNS::RecordType::NS.value)
    DNS::Packet::Question.from_slice(question.to_slice).name.should eq ""

    query = DNS::Packet::Question.build_query("", DNS::RecordType::NS.value, 7_u16, edns_udp_size: 1232_u16)
    packet = DNS::Packet.from_slice(query)
    packet.query?.should be_true
    packet.query_type.should eq DNS::OpCode::QUERY
    packet.questions.first.type.should eq DNS::RecordType::NS.value
    packet.questions.first.class_code.should eq DNS::ClassCode::Internet.value
    packet.additionals.first.name.should eq ""

    record = DNS::Packet::ResourceRecord.new("printer.local.", 1_u16, 1_u16, 5.seconds, resource_data: Bytes[192, 0, 2, 1])
    decoded = DNS::Packet::ResourceRecord.from_slice(record.to_slice)
    decoded.name.should eq "printer.local"
    decoded.ip_address.address.should eq "192.0.2.1"
    decoded.to_s.should contain "192.0.2.1"
  end

  it "reads packets from a file and from a positioned memory buffer" do
    bytes = "75c08180000100010000000003777777066e6574627364036f72670000010001c00c00010001000140ef0004cc98be0c".hexbytes
    File.tempfile("dns-packet") do |file|
      file.write(bytes)
      file.rewind
      packet = DNS::Packet.from_io(file)
      packet.success?.should be_true
      packet.answers.first.name.should eq "www.netbsd.org"
    end

    io = IO::Memory.new
    io.write(bytes)
    io.write(bytes)
    io.rewind
    DNS::Packet.from_io(io).answers.first.name.should eq "www.netbsd.org"
    DNS::Packet.from_io(io).answers.first.name.should eq "www.netbsd.org"
    io.pos.should eq bytes.size * 2
  end

  it "rejects an incomplete name and an oversized label" do
    expect_raises(IO::EOFError) { DNS::Resource.read_labels(IO::Memory.new(Bytes[1, 97])) }
    expect_raises(ArgumentError) do
      DNS::Packet::Question.build_query("a" * 64, 1_u16, 7_u16)
    end
  end

  it "recognizes a server error and can decode a name from an explicit offset" do
    packet = DNS::Packet.new(id: 2_u16, response: true, response_code: 2_u8)
    DNS::Packet.from_slice(packet.to_slice).server_error?.should be_true

    name = IO::Memory.new
    name.write_byte(0_u8)
    DNS::Resource.write_labels(name, "resolver.test")
    DNS::Resource.get_labels_from_pointer(1_u16, name.to_slice).should eq "resolver.test"
  end

  it "raises for unrecognized header codes and extended EDNS codes" do
    header_error = DNS::Packet.new(id: 2_u16, response: true, response_code: 6_u8)
    error = expect_raises(DNS::Packet::ResponseError) { header_error.raise_on_error! }
    error.code.should eq 6

    opt = DNS::Packet::ResourceRecord.new("", DNS::RecordType::OPT.value, 1232_u16, (1_u32 << 24).seconds)
    extended = DNS::Packet.new(id: 3_u16, response: true, additionals: [opt])
    packet = DNS::Packet.from_slice(extended.to_slice)
    packet.response_code.should eq 0
    packet.effective_response_code.should eq 16
    packet.success?.should be_false
    expect_raises(DNS::Packet::ResponseError) { packet.raise_on_error! }.code.should eq 16
  end

  it "round-trips EDNS metadata and preserves repeated and unknown options" do
    options = [
      DNS::Packet::EDNS::Option.new(65001_u16, Bytes[1, 2, 3]),
      DNS::Packet::EDNS::Option.new(DNS::Packet::EDNS::EXTENDED_ERROR, Bytes[0, 6]),
      DNS::Packet::EDNS::Option.new(DNS::Packet::EDNS::EXTENDED_ERROR, Bytes[0, 3, 115, 116, 97, 108, 101]),
    ]
    edns = DNS::Packet::EDNS.new(1400_u16, options, version: 1_u8, flags: 1_u16)
    response = DNS::Packet.new(id: 4_u16, response: true, response_code: 2_u8, additionals: [edns.to_resource_record])
    decoded = DNS::Packet.from_slice(response.to_slice)

    parsed = decoded.edns || raise "missing OPT"
    parsed.udp_payload_size.should eq 1400
    parsed.version.should eq 1
    parsed.flags.should eq 1
    parsed.options.should eq options
    error = expect_raises(DNS::Packet::ServerError) { decoded.raise_on_error! }
    error.extended_errors.map(&.code).should eq [6_u16, 3_u16]
    error.extended_errors.map(&.text).should eq [nil, "stale"]
  end

  it "exposes a parsed DNAME target and renders unknown resource data" do
    target = IO::Memory.new
    DNS::Resource.write_labels(target, "target.test")
    dname = DNS::Packet::ResourceRecord.new("alias.test", 39_u16, 1_u16, 10.seconds, resource_data: target.to_slice)
    DNS::Packet::ResourceRecord.from_slice(dname.to_slice).dname.should eq "target.test"

    unknown = DNS::Packet::ResourceRecord.new("resource.test", 65000_u16, 1_u16, 10.seconds, resource_data: Bytes[1, 2])
    unknown.to_s.should contain "Raw Data: 0102"
  end
end

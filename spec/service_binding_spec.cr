require "./spec_helper"
require "./support/dns_stub"

private def binding_bytes(priority : UInt16, target : String, params : Array({UInt16, Bytes})) : Bytes
  io = IO::Memory.new
  io.write_bytes(priority, IO::ByteFormat::BigEndian)
  DNS::Resource.write_labels(io, target)
  params.each do |key, value|
    io.write_bytes(key, IO::ByteFormat::BigEndian)
    io.write_bytes(value.size.to_u16, IO::ByteFormat::BigEndian)
    io.write(value)
  end
  io.to_slice
end

describe DNS::Resource::SVCB do
  it "queries and decodes a typed service binding with address hints and a port" do
    bytes = binding_bytes(1_u16, "target.test", [
      {0_u16, Bytes[0, 3]},
      {1_u16, Bytes[2, 104, 51]},
      {2_u16, Bytes.empty},
      {3_u16, Bytes[0x20, 0xfb]},
      {4_u16, Bytes[192, 0, 2, 1]},
      {6_u16, "20010db8000000000000000000000002".hexbytes},
    ])
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      answer = DNS::Packet::ResourceRecord.new(question.name, DNS::RecordType::SVCB.value, 1_u16, 60.seconds, resource_data: bytes)
      dns_response(query, answers: [answer])
    end
    DNS.default_resolver = udp_resolver(stub)

    records = DNS.query("_service.example.test.", [DNS::RecordType::SVCB])
    binding = records.first.resource.as(DNS::Resource::SVCB)
    binding.target_name.should eq "target.test"
    binding.alpn.should eq ["h3"]
    binding.port.should eq 8443
    binding.no_default_alpn?.should be_true
    binding.ipv4_hints.map(&.address).should eq ["192.0.2.1"]
    binding.ipv6_hints.map(&.address).should eq ["2001:db8::2"]
    binding.compatible?.should be_true
    binding.compatible?([1_u16]).should be_false
  ensure
    stub.try(&.close)
  end

  it "preserves unknown parameters and reports an unsupported mandatory key" do
    bytes = binding_bytes(1_u16, ".", [{0_u16, Bytes[0, 9]}, {9_u16, Bytes[1, 2]}])
    binding = DNS::Resource::SVCB.new(bytes, bytes)
    binding.svcparam[9_u16].should eq Bytes[1, 2]
    binding.compatible?.should be_false
    binding.compatible?([9_u16]).should be_true
  end

  it "rejects ordering errors and missing mandatory parameters" do
    duplicate = binding_bytes(1_u16, ".", [{3_u16, Bytes[0, 80]}, {3_u16, Bytes[0, 81]}])
    expect_raises(IO::Error) { DNS::Resource::SVCB.new(duplicate, duplicate) }
    missing = binding_bytes(1_u16, ".", [{0_u16, Bytes[0, 3]}])
    expect_raises(IO::Error) { DNS::Resource::SVCB.new(missing, missing) }
  end

  it "drops the malformed RRset and keeps other usable answers" do
    name = "service.test"
    malformed = binding_bytes(1_u16, ".", [{0_u16, Bytes[0, 3]}])
    valid = binding_bytes(1_u16, ".", [{3_u16, Bytes[0, 80]}])
    type = DNS::RecordType::SVCB.value
    bindings = [malformed, valid].map do |data|
      DNS::Packet::ResourceRecord.new(name, type, 1_u16, 60.seconds, resource_data: data)
    end
    response = DNS::Packet.new(id: 7_u16, response: true, answers: bindings + [a_answer(name)])

    DNS::Packet.from_slice(response.to_slice).answers.map(&.record_type).should eq [DNS::RecordType::A]
  end
end

describe DNS::Resource::HTTPS do
  it "checks automatically mandatory HTTPS keys and exposes alias mode" do
    bytes = binding_bytes(1_u16, ".", [{3_u16, Bytes[1, 187]}])
    binding = DNS::Resource::HTTPS.new(bytes, bytes)
    binding.compatible?([1_u16]).should be_false
    binding.compatible?([3_u16]).should be_true

    alias_bytes = binding_bytes(0_u16, "redirect.test", [] of {UInt16, Bytes})
    target = DNS::Resource::HTTPS.new(alias_bytes, alias_bytes)
    target.alias_mode?.should be_true
    target.target_name.should eq "redirect.test"
  end
end

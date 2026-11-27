require "./spec_helper"
require "./support/dns_stub"

private def soa_answer(zone : String, ttl : Int32 = 60, minimum : Int32 = 60)
  data = IO::Memory.new
  DNS::Resource.write_labels(data, "ns.#{zone}")
  DNS::Resource.write_labels(data, "hostmaster.#{zone}")
  {1, 60, 60, 300, minimum}.each do |value|
    data.write_bytes(value.to_u32, IO::ByteFormat::BigEndian)
  end
  DNS::Packet::ResourceRecord.new(zone, DNS::RecordType::SOA.value, 1_u16, ttl.seconds, resource_data: data.to_slice)
end

describe "negative DNS caching" do
  it "caches NXDOMAIN across types and preserves Extended DNS Errors" do
    stub = DNSStub.new
    ede = DNS::Packet::EDNS::Option.new(DNS::Packet::EDNS::EXTENDED_ERROR, Bytes[0, 15])
    opt = DNS::Packet::EDNS.new(options: [ede]).to_resource_record
    stub.serve_udp do |query, _, _|
      dns_response(query, response_code: 3_u8, authorities: [soa_answer("test")], additionals: [opt])
    end
    DNS.default_resolver = udp_resolver(stub)

    [DNS::RecordType::A, DNS::RecordType::AAAA].each do |type|
      error = expect_raises(DNS::Packet::NameError) { DNS.query("missing.test.", [type]) }
      error.extended_errors.map(&.code).should eq [15_u16]
    end
    stub.request_count.should eq 1
  ensure
    stub.try(&.close)
  end

  it "caches NODATA by type and expires it using the smaller SOA TTL" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      if question.type == DNS::RecordType::A.value
        dns_response(query, authorities: [soa_answer("test", minimum: 1)])
      else
        dns_response(query, answers: [aaaa_answer(question.name)])
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    2.times { DNS.query("nodata.test.", [DNS::RecordType::A]).should be_empty }
    DNS.query("nodata.test.", [DNS::RecordType::AAAA]).map(&.ip_address.address).should eq ["2001:db8::1"]
    stub.request_count.should eq 2

    sleep 1.05.seconds
    DNS.query("nodata.test.", [DNS::RecordType::A]).should be_empty
    stub.request_count.should eq 3
  ensure
    stub.try(&.close)
  end

  it "does not cache a negative response without a covering SOA" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      dns_response(query, response_code: 3_u8, authorities: [soa_answer("unrelated.test")])
    end
    DNS.default_resolver = udp_resolver(stub)

    2.times do
      expect_raises(DNS::Packet::NameError) { DNS.query("missing.test.", [DNS::RecordType::A]) }
    end
    stub.request_count.should eq 2
  ensure
    stub.try(&.close)
  end

  it "caches a CNAME target's NXDOMAIN and leaves the alias queryable" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      alias_record = domain_answer(question.name, DNS::RecordType::CNAME, "target.test")
      if question.type == DNS::RecordType::CNAME.value
        dns_response(query, answers: [alias_record])
      else
        dns_response(query, response_code: 3_u8, answers: [alias_record], authorities: [soa_answer("test")])
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    expect_raises(DNS::Packet::NameError) { DNS.query("alias.test.", [DNS::RecordType::A]) }
    expect_raises(DNS::Packet::NameError) { DNS.query("target.test.", [DNS::RecordType::AAAA]) }
    DNS.query("alias.test.", [DNS::RecordType::CNAME]).map(&.cname).should eq ["target.test"]
    stub.request_count.should eq 2
  ensure
    stub.try(&.close)
  end
end

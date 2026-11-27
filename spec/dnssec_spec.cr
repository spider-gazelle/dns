require "./spec_helper"
require "./support/dns_stub"

private def dnssec_flags(packet : DNS::Packet)
  {packet.edns.try(&.dnssec_ok?) || false, packet.authenticated_data?, packet.checking_disabled?}
end

private def rrsig_answer(name : String)
  rdata = IO::Memory.new
  format = IO::ByteFormat::BigEndian
  rdata.write_bytes(DNS::RecordType::A.value, format)
  rdata.write_byte(8_u8) # RSA/SHA-256
  rdata.write_byte(2_u8) # label count
  {60_u32, 1_900_000_000_u32, 1_700_000_000_u32}.each { |value| rdata.write_bytes(value, format) }
  rdata.write_bytes(100_u16, format)
  DNS::Resource.write_labels(rdata, "test")
  rdata.write(Bytes[1, 2, 3])
  DNS::Packet::ResourceRecord.new(name, DNS::RecordType::RRSIG.value, 1_u16, 60.seconds, resource_data: rdata.to_slice)
end

describe DNS::DNSSEC do
  it "sets DO, AD and CD without replacing existing EDNS metadata" do
    padding = DNS::Packet::EDNS::Option.new(12_u16, Bytes[0, 0])
    edns = DNS::Packet::EDNS.new(1400_u16, [padding], flags: 1_u16)
    dnssec = DNS::DNSSEC::Options.new(dnssec_ok: true, request_ad: true, checking_disabled: true)
    query = DNS::Packet::Question.build_query("secure.test", 1_u16, 42_u16, edns: edns, dnssec: dnssec)
    packet = DNS::Packet.from_slice(query)
    dnssec_flags(packet).should eq({true, true, true})
    dnssec_flags(DNS::Packet.from_slice(packet.to_slice)).should eq({true, true, true})

    opt = packet.edns || raise "missing OPT"
    opt.flags.should eq 0x8001_u16
    opt.udp_payload_size.should eq 1400_u16
    opt.options.should eq [padding]
    edns.dnssec_ok?.should be_false
  end

  it "keeps DNSSEC flags on TCP fallback and preserves signature records" do
    stub = DNSStub.new
    observed = [] of {Bool, Bool, Bool}
    signature = rrsig_answer("secure.test")
    stub.serve_udp do |query, _, _|
      observed << dnssec_flags(query)
      dns_response(query, truncated: true)
    end
    stub.serve_tcp do |query|
      observed << dnssec_flags(query)
      dns_response(query, answers: [a_answer("secure.test"), signature],
        additionals: [DNS::Packet::EDNS.new.to_resource_record], authenticated_data: true)
    end
    dnssec = DNS::DNSSEC::Options.new(dnssec_ok: true, request_ad: true)

    packet = DNS.query_packet("secure.test.", DNS::RecordType::A, resolver: udp_resolver(stub), dnssec: dnssec)
    packet.authenticated_data?.should be_true
    packet.answers.find!(&.record_type.rrsig?).resource_data.should eq signature.resource_data
    observed.should eq [{true, true, false}, {true, true, false}]
  ensure
    stub.try(&.close)
  end

  it "tries another server with DO when the first server rejects EDNS" do
    primary = DNSStub.new
    backup = DNSStub.new("::1", primary.port)
    observed = [] of {Bool, Bool, Bool}
    primary.serve_udp do |query, _, _|
      observed << dnssec_flags(query)
      dns_response(query, response_code: 1_u8, questions: [] of DNS::Packet::Question)
    end
    backup.serve_udp do |query, _, _|
      observed << dnssec_flags(query)
      dns_response(query, answers: [a_answer("secure.test")], additionals: [DNS::Packet::EDNS.new.to_resource_record])
    end
    servers = ["127.0.0.1", "::1"]
    resolver = DNS::Resolver::UDP.new(servers, port: primary.port.to_u16)
    resolver.server_config = DNS::Servers.new(servers, attempts: 1)

    packet = DNS.query_packet(
      "secure.test.",
      DNS::RecordType::A,
      resolver: resolver,
      dnssec: DNS::DNSSEC::Options.new(dnssec_ok: true),
    )
    packet.answers.map(&.ip_address.address).should eq ["93.184.216.34"]
    observed.should eq [{true, false, false}, {true, false, false}]
  ensure
    backup.try(&.close)
    primary.try(&.close)
  end

  it "does not retry a silent DO query without EDNS" do
    stub = DNSStub.new
    observed = [] of {Bool, Bool, Bool}
    stub.serve_udp do |query, _, _|
      observed << dnssec_flags(query)
      nil
    end

    expect_raises(IO::TimeoutError) do
      udp_resolver(stub).query("secure.test", "127.0.0.1", {1_u16 => 1_u16}, 350.milliseconds,
        dnssec: DNS::DNSSEC::Options.new(dnssec_ok: true)) { |_| raise "unexpected reply" }
    end
    observed.should eq [{true, false, false}]
  ensure
    stub.try(&.close)
  end

  it "reports a failed DNSSEC EDNS exchange when a reply omits OPT" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, answers: [a_answer("secure.test")]) }
    resolver = udp_resolver(stub)

    expect_raises(DNS::Packet::ServerError, /did not provide EDNS/) do
      DNS.query_packet("secure.test.", DNS::RecordType::A,
        resolver: resolver, dnssec: DNS::DNSSEC::Options.new(dnssec_ok: true))
    end
    stub.request_count.should eq 1
  ensure
    stub.try(&.close)
  end

  it "retains the AD request and CD bits when an AD/CD-only query falls back" do
    stub = DNSStub.new
    headers = [] of {Bool, Bool, Bool}
    had_opt = [] of Bool
    stub.serve_udp do |query, _, _|
      headers << dnssec_flags(query)
      had_opt << !query.edns.nil?
      if query.edns
        dns_response(query, response_code: 1_u8)
      else
        dns_response(query, answers: [a_answer("secure.test")])
      end
    end
    resolver = udp_resolver(stub)
    DNS.query_packet("secure.test", DNS::RecordType::A,
      resolver: resolver, dnssec: DNS::DNSSEC::Options.new(request_ad: true, checking_disabled: true))

    had_opt.should eq [true, false]
    headers.should eq [{false, true, true}, {false, true, true}]
  ensure
    stub.try(&.close)
  end

  it "keeps packet queries separate from normal and negative caches" do
    stub = DNSStub.new
    denial = DNS::Packet::ResourceRecord.new("missing.test", DNS::RecordType::NSEC.value, 1_u16, 60.seconds,
      resource_data: Bytes[0, 0, 1, 0x40])
    stub.serve_udp do |query, _, _|
      if query.checking_disabled?
        dns_response(query, response_code: 3_u8, authorities: [denial], authenticated_data: true)
      else
        dns_response(query, answers: [a_answer("missing.test", {192_u8, 0_u8, 2_u8, 10_u8})])
      end
    end
    DNS.default_resolver = udp_resolver(stub)
    DNS.query("missing.test.", [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.10"

    dnssec = DNS::DNSSEC::Options.new(checking_disabled: true)
    2.times do
      packet = DNS.query_packet("missing.test.", DNS::RecordType::A, dnssec: dnssec)
      packet.effective_response_code.should eq 3_u16
      packet.authorities.first.record_type.should eq DNS::RecordType::NSEC
      packet.authenticated_data?.should be_true
    end
    DNS.query("missing.test.", [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.10"
    stub.request_count.should eq 3
  ensure
    stub.try(&.close)
  end

  it "rejects DNSSEC flags on a resolver without wire-level support" do
    options = DNS::DNSSEC::Options.new(request_ad: true)
    expect_raises(DNS::DNSSEC::UnsupportedResolver) do
      DNS.query_packet("printer.local.", DNS::RecordType::A, dnssec: options)
    end
  end
end

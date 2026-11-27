require "./spec_helper"
require "./support/dns_stub"

private class SystemFallbackProbe < DNS::Resolver::UDP
  getter attempted = [] of String

  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    & : DNS::Packet ->
  )
    @attempted << dns_server
    raise IO::TimeoutError.new("first server timed out") if @attempted.size == 1

    fetch.each do |id, type|
      record = DNS::Packet::ResourceRecord.new(domain, type, 1_u16, 1.minute)
      yield DNS::Packet.new(id: id, response: true, answers: [record])
    end
  end
end

describe DNS do
  it "should select the appropriate resolver" do
    DNS.select_resolver("starling-home-hub.local").is_a?(DNS::Resolver::MDNS).should be_true
    DNS.select_resolver("www.example.test").is_a?(DNS::Resolver::UDP).should be_true
  end

  it "uses the current global timeout unless the resolver has an override" do
    previous = DNS.timeout
    resolver = DNS::Resolver::UDP.new(["127.0.0.1"])
    resolver.server_config = DNS::Servers.new(["127.0.0.1"])
    DNS.timeout = 7.seconds
    resolver.base_timeout.should eq 7.seconds
    resolver.server_config.timeout = 4.seconds
    DNS.timeout = 9.seconds
    resolver.base_timeout.should eq 4.seconds
  ensure
    DNS.timeout = previous if previous
  end

  it "returns host file entries" do
    response = DNS.query("LocalHost", [DNS::RecordType::A])
    response.size.should eq 1
    response.first.ip_address.address.should eq "127.0.0.1"
  end

  it "should not perform queries for IP addresses" do
    response = DNS.query("127.0.0.1", [DNS::RecordType::A])
    response.size.should eq 1
    response.first.ip_address.address.should eq "127.0.0.1"

    response = DNS.query("::1", [DNS::RecordType::AAAA])
    response.size.should eq 1
    response.first.ip_address.address.should eq "::1"

    response = DNS.query("127.0.0.1", [DNS::RecordType::AAAA])
    response.size.should eq 0

    response = DNS.query("::1", [DNS::RecordType::A])
    response.size.should eq 0
  end

  it "queries for A, AAAA and HTTPS records" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      answer = case question.type
               when  1 then a_answer(question.name)
               when 28 then aaaa_answer(question.name)
               else         DNS::Packet::ResourceRecord.new(question.name, 65_u16, 1_u16, 60.seconds, resource_data: Bytes[0, 1, 0])
               end
      dns_response(query, answers: [answer])
    end
    DNS.default_resolver = udp_resolver(stub)

    answers = DNS.query("records.test.", [DNS::RecordType::A, DNS::RecordType::AAAA, DNS::RecordType::HTTPS])
    answers.map(&.record_type).sort!.should eq [DNS::RecordType::A, DNS::RecordType::AAAA, DNS::RecordType::HTTPS]
    answers.find!(&.record_type.https?).resource.as(DNS::Resource::HTTPS).priority.should eq 1
  ensure
    stub.try(&.close)
  end

  it "queries for MX records and caches the additional address without another query" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      exchange = "mail.exchange.test"
      data = IO::Memory.new
      data.write_bytes(10_u16, IO::ByteFormat::BigEndian)
      DNS::Resource.write_labels(data, exchange)
      answer = DNS::Packet::ResourceRecord.new("exchange.test", 15_u16, 1_u16, 60.seconds, resource_data: data.to_slice)
      dns_response(query, answers: [answer], additionals: [a_answer(exchange)])
    end
    DNS.default_resolver = udp_resolver(stub)

    answers = DNS.query("exchange.test.", [DNS::RecordType::MX])
    answers.map(&.record_type).should eq [DNS::RecordType::MX]
    answers.first.resource.as(DNS::Resource::MX).exchange.should eq "mail.exchange.test"
    DNS.query("mail.exchange.test.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    stub.request_count.should eq 1
  ensure
    stub.try(&.close)
  end

  it "demotes an unresponsive loopback server" do
    primary = DNSStub.new
    backup = DNSStub.new("::1", primary.port)
    primary.serve_udp { |_, _, _| nil }
    backup.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer(query.questions.first.name)])
    end

    servers = ["127.0.0.1", "::1"]
    resolver = DNS::Resolver::UDP.new(servers, port: primary.port.to_u16)
    resolver.server_config = DNS::Servers.new(servers, timeout: 1.second, attempts: 1)
    resolver.failure_limit = 1
    DNS.default_resolver = resolver

    DNS.query("address.test.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    resolver.servers.should eq ["::1", "127.0.0.1"]
  ensure
    primary.try(&.close)
    backup.try(&.close)
  end

  it "handles NXDOMAIN responses" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, response_code: 3_u8) }
    DNS.default_resolver = udp_resolver(stub)

    expect_raises(DNS::Packet::NameError, "Hostname lookup for missing.test failed") do
      DNS.query("missing.test.", [DNS::RecordType::A, DNS::RecordType::AAAA])
    end
  ensure
    stub.try(&.close)
  end

  it "builds the correct IPv4 reverse name" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      if question.type == DNS::RecordType::PTR.value && question.name == "1.2.0.192.in-addr.arpa"
        dns_response(query, answers: [domain_answer(question.name, DNS::RecordType::PTR, "ipv4.test")])
      else
        dns_response(query, response_code: 3_u8)
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    DNS.reverse_lookup(Socket::IPAddress.new("192.0.2.1", 0)).should eq ["ipv4.test"]
  ensure
    stub.try(&.close)
  end

  it "builds the correct IPv6 reverse name" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      reverse_name = "1." + ("0." * 23) + "8.b.d.0.1.0.0.2.ip6.arpa"
      if question.type == DNS::RecordType::PTR.value && question.name == reverse_name
        dns_response(query, answers: [domain_answer(question.name, DNS::RecordType::PTR, "ipv6.test")])
      else
        dns_response(query, response_code: 3_u8)
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    DNS.reverse_lookup(Socket::IPAddress.new("2001:db8::1", 0)).should eq ["ipv6.test"]
  ensure
    stub.try(&.close)
  end

  it "uses native addrinfo for localhost" do
    fallback = DNS::Resolver::UDP.new([] of String)
    resolver = DNS::Resolver::System.new(fallback)
    DNS.default_resolver = resolver
    answers = [] of DNS::Packet::ResourceRecord

    resolver.query("localhost", "127.0.0.1", {1_u16 => DNS::RecordType::A.value}, 2.seconds) do |packet|
      answers.concat(packet.answers)
    end
    addresses = answers.map(&.ip_address.address)
    addresses.should contain "127.0.0.1"
  end

  it "retries non-address questions via the system resolver's next fallback server" do
    servers = ["127.0.0.1", "127.0.0.2"]
    fallback = SystemFallbackProbe.new(servers)
    resolver = DNS::Resolver::System.new(fallback: fallback)
    resolver.server_config = DNS::Servers.new(servers, attempts: 1)
    DNS.default_resolver = resolver

    DNS.query("exchange.test.", [DNS::RecordType::MX]).map(&.record_type).should eq [DNS::RecordType::MX]
    fallback.attempted.should eq servers
  end
end

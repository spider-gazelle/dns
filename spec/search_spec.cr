require "./spec_helper"
require "./support/dns_stub"

describe "DNS search" do
  it "does not reuse an absolute answer after switching resolvers" do
    first = DNSStub.new
    second = DNSStub.new
    first.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer(query.questions.first.name, {192_u8, 0_u8, 2_u8, 1_u8})])
    end
    second.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer(query.questions.first.name, {192_u8, 0_u8, 2_u8, 2_u8})])
    end
    domain = "split-horizon.test."
    DNS.default_resolver = udp_resolver(first)
    DNS.query(domain, [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.1"

    DNS.default_resolver = udp_resolver(second)
    DNS.query(domain, [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.2"
    DNS.query(domain, [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.2"
    second.request_count.should eq 1
  ensure
    first.try(&.close)
    second.try(&.close)
  end

  it "tries later suffixes after an empty answer and keeps the complete cached answer" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      if question.name.ends_with?(".second.test")
        dns_response(query, answers: [a_answer(question.name), a_answer(question.name, {192_u8, 0_u8, 2_u8, 80_u8})])
      else
        dns_response(query)
      end
    end
    resolver = udp_resolver(stub)
    resolver.server_config.search = ["first.test", "second.test"]
    DNS.default_resolver = resolver

    expected = ["93.184.216.34", "192.0.2.80"]
    DNS.query("search-host", [DNS::RecordType::A]).map(&.ip_address.address).should eq expected
    stub.request_count.should eq 2
    DNS.query("search-host", [DNS::RecordType::A]).map(&.ip_address.address).should eq expected
    stub.request_count.should eq 3 # only the first, empty suffix is queried again
    DNS.query("search-host.second.test.", [DNS::RecordType::A]).map(&.ip_address.address).should eq expected
    stub.request_count.should eq 3
  ensure
    stub.try(&.close)
  end

  it "isolates search results from absolute lookups, changed suffixes, and other resolvers" do
    first = DNSStub.new
    second = DNSStub.new
    first.serve_udp do |query, _, _|
      name = query.questions.first.name
      octet = name.ends_with?(".first.test") ? 1_u8 : 2_u8
      dns_response(query, answers: [a_answer(name, {192_u8, 0_u8, 2_u8, octet})])
    end
    second.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer(query.questions.first.name, {192_u8, 0_u8, 2_u8, 3_u8})])
    end
    resolver = udp_resolver(first)
    resolver.server_config.search = ["first.test"]
    DNS.default_resolver = resolver
    DNS.query("search-host", [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.1"
    DNS.query("search-host.", [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.2"

    resolver.server_config.search = ["second.test"]
    DNS.query("search-host", [DNS::RecordType::A]).first.name.should eq "search-host.second.test"

    resolver = udp_resolver(second)
    resolver.server_config.search = ["first.test"]
    DNS.default_resolver = resolver
    DNS.query("search-host", [DNS::RecordType::A]).first.ip_address.address.should eq "192.0.2.3"
  ensure
    first.try(&.close)
    second.try(&.close)
  end
end

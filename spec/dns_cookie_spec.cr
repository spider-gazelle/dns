require "./spec_helper"
require "./support/dns_stub"

private def cookie_option(query : DNS::Packet)
  query.edns.try(&.option(DNS::Packet::EDNS::COOKIE))
end

private def server_cookie(client : DNS::Packet::EDNS::Option, marker : UInt8 = 95_u8)
  data = Bytes.new(16, marker)
  data[0, 8].copy_from(client.data[0, 8])
  DNS::Packet::EDNS::Option.new(DNS::Packet::EDNS::COOKIE, data)
end

private def cookie_opt(cookie : DNS::Packet::EDNS::Option, *, bad = false)
  DNS::Packet::EDNS.new(options: [cookie], extended_rcode: bad ? 1_u8 : 0_u8).to_resource_record
end

describe "UDP DNS Cookies" do
  it "retries BADCOOKIE with the server cookie and reuses it for later queries" do
    stub = DNSStub.new
    sent = [] of Bytes
    stub.serve_udp do |query, count, _|
      if option = cookie_option(query)
        sent << option.data
        opt = cookie_opt(server_cookie(option), bad: count == 1)
        if count == 1
          dns_response(query, response_code: 7_u8, additionals: [opt])
        else
          dns_response(query, answers: [a_answer(query.questions.first.name)], additionals: [opt])
        end
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    {"initial.test.", "later.test."}.each do |name|
      DNS.query(name, [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    end
    sent.map(&.size).should eq [8, 16, 16]
    sent[1][0, 8].should eq sent[0]
    sent[2].should eq sent[1]
  ensure
    stub.try(&.close)
  end

  it "ignores mismatched and missing cookies once the server has negotiated a cookie" do
    stub = DNSStub.new
    stub.serve_udp do |query, count, source|
      if option = cookie_option(query)
        name = query.questions.first.name
        if count > 1
          wrong = server_cookie(option)
          wrong.data[0] = wrong.data[0] ^ 1_u8
          old_address = a_answer(name, {192_u8, 0_u8, 2_u8, 1_u8})
          stub.reply(dns_response(query, answers: [old_address], additionals: [cookie_opt(wrong)]), source)
          stub.reply(dns_response(query, answers: [old_address]), source)
        end
        dns_response(query, answers: [a_answer(name)], additionals: [cookie_opt(server_cookie(option))])
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    {"initial.test.", "protected.test."}.each do |name|
      DNS.query(name, [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    end
    stub.request_count.should eq 2
  ensure
    stub.try(&.close)
  end

  it "uses TCP after a second BADCOOKIE response" do
    stub = DNSStub.new
    stub.serve_udp do |query, count, _|
      if option = cookie_option(query)
        opt = cookie_opt(server_cookie(option, count.to_u8), bad: true)
        dns_response(query, response_code: 7_u8, additionals: [opt])
      end
    end
    stub.serve_tcp do |query|
      dns_response(query, answers: [a_answer(query.questions.first.name)])
    end
    DNS.default_resolver = udp_resolver(stub)

    DNS.query("retry.test.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    stub.request_count.should eq 2
  ensure
    stub.try(&.close)
  end

  it "stops sending cookies to a server that ignores the option" do
    stub = DNSStub.new
    sizes = [] of Int32
    stub.serve_udp do |query, _, _|
      sizes << (cookie_option(query).try(&.data.size) || 0)
      dns_response(query, answers: [a_answer(query.questions.first.name)])
    end
    DNS.default_resolver = udp_resolver(stub)

    {"initial.test.", "legacy.test."}.each do |name|
      DNS.query(name, [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    end
    sizes.should eq [8, 0]
  ensure
    stub.try(&.close)
  end

  it "can disable cookie negotiation while preserving EDNS options on TCP fallback" do
    stub = DNSStub.new
    padding = DNS::Packet::EDNS::Option.new(12_u16, Bytes[0, 0])
    seen = [] of Array(DNS::Packet::EDNS::Option)
    stub.serve_udp do |query, _, _|
      seen << (query.edns.try(&.options) || [] of DNS::Packet::EDNS::Option)
      dns_response(query, truncated: true)
    end
    stub.serve_tcp do |query|
      seen << (query.edns.try(&.options) || [] of DNS::Packet::EDNS::Option)
      dns_response(query, answers: [a_answer(query.questions.first.name)])
    end
    resolver = udp_resolver(stub)
    resolver.edns_options = [padding]
    resolver.dns_cookies = false
    DNS.default_resolver = resolver

    DNS.query("fallback.test.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    seen.should eq [[padding], [padding]]
  ensure
    stub.try(&.close)
  end
end

require "./spec_helper"
require "./support/dns_stub"

describe DNS::Resolver::MDNS do
  it "routes an expanded .local candidate to mDNS" do
    unicast = DNSStub.new
    multicast = DNSStub.new
    multicast.serve_udp do |query, _, _|
      name = query.questions.first.name
      dns_response(query, answers: [a_answer(name)])
    end
    resolver = udp_resolver(unicast)
    resolver.server_config.search = ["office.local"]
    DNS.default_resolver = resolver

    pattern = DNS.resolvers.keys.find!(&.matches?("printer.office.local"))
    original = DNS.resolvers[pattern]
    DNS.resolvers[pattern] = DNS::Resolver::MDNS.new(["127.0.0.1"], multicast.port.to_u16)

    DNS.query("printer", [DNS::RecordType::A]).map(&.name).should eq ["printer.office.local"]
    multicast.request_count.should eq 1
    unicast.request_count.should eq 0
  ensure
    DNS.resolvers[pattern] = original if pattern && original
    unicast.try(&.close)
    multicast.try(&.close)
  end

  {% if flag?(:linux) %}
    it "sends to the mDNS multicast group over the configured interface" do
      group = "224.0.0.251"
      stub = DNSStub.new("0.0.0.0", multicast_group: group)
      stub.serve_udp do |query, _, _|
        dns_response(query, answers: [a_answer(query.questions.first.name)])
      end
      resolver = DNS::Resolver::MDNS.new([group], stub.port.to_u16, ipv4_interface: "127.0.0.1")
      answers = [] of DNS::Packet::ResourceRecord
      resolver.query("printer.local", group, {1_u16 => 1_u16}, 1.second) do |packet|
        answers.concat(packet.answers)
      end
      answers.map(&.name).should eq ["printer.local"]
      stub.request_count.should eq 1
    ensure
      stub.try(&.close)
    end
  {% end %}

  it "resolves an absolute .local name when one reply contains A and AAAA" do
    stub = DNSStub.new
    stub.serve_udp do |query, count, _|
      if count == 2
        name = query.questions.first.name
        dns_response(query, answers: [a_answer(name), aaaa_answer(name)])
      end
    end

    name = "printer.local."
    pattern = DNS.resolvers.keys.find!(&.matches?(name.rchop('.')))
    original = DNS.resolvers[pattern]
    resolver = DNS::Resolver::MDNS.new(["127.0.0.1"], stub.port.to_u16)
    DNS.resolvers[pattern] = resolver

    DNS.select_resolver(name).should be(resolver)
    DNS.query(name, [DNS::RecordType::A, DNS::RecordType::AAAA])
      .map(&.ip_address.address).sort!.should eq ["2001:db8::1", "93.184.216.34"]
    stub.request_count.should eq 2
  ensure
    DNS.resolvers[pattern] = original if pattern && original
    stub.try(&.close)
  end

  it "waits for each requested type when a reply is duplicated" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, source|
      name = query.questions.first.name
      answer = query.questions.first.type == 1 ? a_answer(name) : aaaa_answer(name)
      packet = dns_response(query, answers: [answer])
      stub.reply(packet, source) if answer.type == 1
      packet
    end

    resolver = DNS::Resolver::MDNS.new(["127.0.0.1"], stub.port.to_u16)
    types = [] of UInt16
    resolver.query("printer.local", "127.0.0.1", {1_u16 => 1_u16, 2_u16 => 28_u16}, 1.second) do |reply|
      types.concat(reply.answers.map(&.type))
    end
    types.sort.should eq [1_u16, 28_u16]
  ensure
    stub.try(&.close)
  end

  it "returns a single address family after the response window closes" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer("printer.local")]) if query.questions.first.type == 1
    end
    resolver = DNS::Resolver::MDNS.new(["127.0.0.1"], stub.port.to_u16)
    types = [] of UInt16
    resolver.query("printer.local", "127.0.0.1", {1_u16 => 1_u16, 2_u16 => 28_u16}, 250.milliseconds) do |reply|
      types.concat(reply.answers.map(&.type))
    end
    types.should eq [1_u16]
  ensure
    stub.try(&.close)
  end
end

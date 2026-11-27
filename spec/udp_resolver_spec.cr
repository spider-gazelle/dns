require "./spec_helper"
require "./support/dns_stub"

# A test-only resource lets the reader exercise a decoder failure with a
# properly framed response.
struct DNSStubFailingResource
  include DNS::Resource

  RECORD_TYPE = 65280_u16

  def initialize(resource_data : Bytes, message : Bytes)
    raise IO::Error.new("simulated resource decoder failure")
  end
end

describe DNS::Resolver::UDP do
  it "resolves a query over the shared UDP socket" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, answers: [a_answer]) }
    resolver = udp_resolver(stub)

    responses = [] of DNS::Packet
    resolver.query("example.com", "127.0.0.1", {7_u16 => 1_u16}, 2.seconds) { |reply| responses << reply }

    responses.size.should eq 1
    # the wire id is remapped back to the caller's logical request id
    responses.first.id.should eq 7_u16
    responses.first.answers.first.ip_address.address.should eq "93.184.216.34"
  ensure
    stub.try(&.close)
  end

  it "reuses a single source port across queries (shared port)" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, answers: [a_answer]) }
    resolver = udp_resolver(stub)

    3.times do |i|
      resolver.query("example.com", "127.0.0.1", {(i + 1).to_u16 => 1_u16}, 2.seconds) { |_| }
    end

    stub.source_ports.size.should eq 3
    stub.source_ports.uniq.size.should eq 1
  ensure
    stub.try(&.close)
  end

  it "ignores a response with a mismatched transaction id" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, id: query.id &+ 1_u16, answers: [a_answer]) }
    resolver = udp_resolver(stub)

    expect_raises(IO::TimeoutError) do
      resolver.query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 300.milliseconds) { |_| }
    end
  ensure
    stub.try(&.close)
  end

  it "ignores a response whose question does not match" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      dns_response(query,
        questions: [DNS::Packet::Question.new("evil.example", 1_u16, 1_u16)],
        answers: [a_answer("evil.example")])
    end
    resolver = udp_resolver(stub)

    expect_raises(IO::TimeoutError) do
      resolver.query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 300.milliseconds) { |_| }
    end
  ensure
    stub.try(&.close)
  end

  it "ignores replies from another port and replies with the wrong question class" do
    stub = DNSStub.new
    alternate = DNSStub.new
    stub.serve_udp do |query, _, source|
      question = query.questions.first
      wrong_class = DNS::Packet::Question.new(question.name, question.type, DNS::ClassCode::Chaos.value)
      alternate.reply(dns_response(query, answers: [a_answer(question.name, {192_u8, 0_u8, 2_u8, 1_u8})]), source)
      stub.reply(dns_response(query, questions: [wrong_class], answers: [a_answer(question.name, {192_u8, 0_u8, 2_u8, 2_u8})]), source)
      dns_response(query, answers: [a_answer(question.name)])
    end

    results = [] of String
    udp_resolver(stub).query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 1.second) do |reply|
      results.concat(reply.answers.map(&.ip_address.address))
    end
    results.should eq ["93.184.216.34"]
  ensure
    alternate.try(&.close)
    stub.try(&.close)
  end

  it "ignores short datagrams and continues to receive subsequent replies" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, source|
      stub.reply(Bytes[0, 0, 0], source)
      dns_response(query, answers: [a_answer(query.questions.first.name)])
    end

    resolver = udp_resolver(stub)
    2.times do
      responses = [] of DNS::Packet
      resolver.query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 1.second) { |reply| responses << reply }
      responses.size.should eq 1
    end
  ensure
    stub.try(&.close)
  end

  it "continues reading after one resource decoder rejects a response" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, source|
      name = query.questions.first.name
      record = DNS::Packet::ResourceRecord.new(name, DNSStubFailingResource::RECORD_TYPE, 1_u16, 1.minute)
      stub.reply(dns_response(query, additionals: [record]), source)
      dns_response(query, answers: [a_answer(name)])
    end

    responses = [] of DNS::Packet
    udp_resolver(stub).query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 1.second) { |reply| responses << reply }
    responses.flat_map(&.answers).map(&.ip_address.address).should eq ["93.184.216.34"]
  ensure
    stub.try(&.close)
  end

  it "recreates the shared socket if its receive loop shuts down" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, answers: [a_answer]) }
    resolver = udp_resolver(stub)
    fetch = {1_u16 => 1_u16}
    resolver.query("example.com", "127.0.0.1", fetch, 1.second) { |_| }

    shared = DNS::Resolver::UDP::SharedSocket.instance
    socket = shared.@v4 || raise "missing shared socket"
    socket.close
    deadline = Time.instant + 1.second
    until shared.@v4.nil?
      raise "shared socket was not retired" if Time.instant >= deadline
      Fiber.yield
    end

    responses = [] of DNS::Packet
    resolver.query("example.com", "127.0.0.1", fetch, 1.second) { |reply| responses << reply }
    responses.size.should eq 1
  ensure
    stub.try(&.close)
  end

  it "demultiplexes many concurrent queries over the shared socket" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, answers: [a_answer(query.questions.first.name)]) }
    resolver = udp_resolver(stub)

    names = (0...20).map { |i| "host#{i}.example" }
    done = Channel({String, String}).new

    names.each do |name|
      spawn do
        result = ""
        resolver.query(name, "127.0.0.1", {1_u16 => 1_u16}, 3.seconds) do |reply|
          result = reply.questions.first.name
        end
        done.send({name, result})
      end
    end

    names.size.times do
      asked, got = select
      when result = done.receive
        result
      when timeout(4.seconds)
        raise "concurrent UDP lookup did not complete"
      end
      got.should eq asked # each fiber received its own response - no cross-talk
    end
  ensure
    stub.try(&.close)
  end

  it "retries the server when both probes in the first attempt are dropped" do
    stub = DNSStub.new
    stub.serve_udp { |query, count, _| count <= 2 ? nil : dns_response(query, answers: [a_answer]) }

    resolver = DNS::Resolver::UDP.new(["127.0.0.1"], port: stub.port.to_u16)
    resolver.server_config = DNS::Servers.new(["127.0.0.1"], timeout: 1.second, attempts: 3)

    responses = [] of DNS::Packet
    resolver.select_server do |server, timeout|
      resolver.query("example.com", server, {1_u16 => 1_u16}, timeout) { |reply| responses << reply }
    end

    responses.size.should eq 1
    stub.request_count.should eq 3
  ensure
    stub.try(&.close)
  end

  it "retries without EDNS after a legacy FORMERR without a question" do
    stub = DNSStub.new
    used_edns = [] of Bool
    stub.serve_udp do |query, _, _|
      edns = !query.additionals.empty?
      used_edns << edns
      if edns
        dns_response(query, response_code: 1_u8, questions: [] of DNS::Packet::Question)
      else
        dns_response(query, answers: [a_answer])
      end
    end
    DNS.default_resolver = udp_resolver(stub)

    DNS.query("example.com.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    used_edns.should eq [true, false]
  ensure
    stub.try(&.close)
  end

  it "tries legacy DNS when the EDNS probe receives no reply" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer]) if query.additionals.empty?
    end
    responses = [] of DNS::Packet

    udp_resolver(stub).query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 500.milliseconds) { |packet| responses << packet }
    responses.size.should eq 1
    stub.request_count.should eq 2
  ensure
    stub.try(&.close)
  end

  it "can still use an EDNS response after the legacy retry starts" do
    stub = DNSStub.new
    original : DNS::Packet? = nil
    stub.serve_udp do |query, _, _|
      if query.additionals.empty?
        if edns_query = original
          dns_response(edns_query, answers: [a_answer])
        end
      else
        original = query
        nil
      end
    end
    responses = [] of DNS::Packet

    udp_resolver(stub).query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 500.milliseconds) { |packet| responses << packet }
    responses.size.should eq 1
    stub.request_count.should eq 2
  ensure
    stub.try(&.close)
  end

  it "uses legacy TCP when a BADVERS reply leads to a truncated legacy UDP response" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      if query.additionals.empty?
        dns_response(query, truncated: true)
      else
        opt = DNS::Packet::ResourceRecord.new("", DNS::RecordType::OPT.value, 1232_u16, (1_u32 << 24).seconds)
        dns_response(query, additionals: [opt])
      end
    end
    tcp_options = [] of Int32
    stub.serve_tcp do |query|
      tcp_options << query.additionals.size
      dns_response(query, answers: [a_answer])
    end
    DNS.default_resolver = udp_resolver(stub)

    DNS.query("example.com.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["93.184.216.34"]
    stub.request_count.should eq 2
    tcp_options.should eq [0]
  ensure
    stub.try(&.close)
  end

  it "falls back to TCP when the UDP response is truncated" do
    stub = DNSStub.new
    stub.serve_udp { |query, _, _| dns_response(query, truncated: true) } # TC=1, no answers
    stub.serve_tcp { |query| dns_response(query, answers: [a_answer]) }
    resolver = udp_resolver(stub)

    responses = [] of DNS::Packet
    resolver.query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 2.seconds) { |reply| responses << reply }

    responses.size.should eq 1
    responses.first.truncation?.should be_false
    responses.first.answers.size.should eq 1
  ensure
    stub.try(&.close)
  end

  it "stops after the configured number of attempts when no server replies" do
    stub = DNSStub.new
    stub.serve_udp { |_, _, _| nil }
    resolver = udp_resolver(stub, timeout: 1.second, attempts: 2)
    resolver.failure_limit = 3

    expect_raises(IO::TimeoutError) do
      resolver.select_server do |server, timeout|
        resolver.query("example.com", server, {1_u16 => 1_u16}, timeout) { raise "unexpected answer" }
      end
    end
    stub.request_count.should eq 4
    resolver.failure_counts["127.0.0.1"].should eq 2
  ensure
    stub.try(&.close)
  end

  it "tries the next server when TCP fallback does not answer the UDP question" do
    primary = DNSStub.new
    backup = DNSStub.new("::1", primary.port)
    primary.serve_udp { |query, _, _| dns_response(query, truncated: true, answers: [a_answer]) }
    primary.serve_tcp do |query|
      wrong = DNS::Packet::Question.new("other.example", 1_u16)
      dns_response(query, questions: [wrong], answers: [a_answer("other.example")])
    end
    backup.serve_udp do |query, _, _|
      dns_response(query, answers: [a_answer(query.questions.first.name, {192_u8, 0_u8, 2_u8, 12_u8})])
    end
    servers = ["127.0.0.1", "::1"]
    resolver = DNS::Resolver::UDP.new(servers, port: primary.port.to_u16)
    resolver.server_config = DNS::Servers.new(servers, attempts: 1)
    DNS.default_resolver = resolver

    DNS.query("example.com.", [DNS::RecordType::A]).map(&.ip_address.address).should eq ["192.0.2.12"]
    primary.request_count.should eq 1
    backup.request_count.should eq 1
  ensure
    backup.try(&.close)
    primary.try(&.close)
  end

  it "uses the remaining attempt time for TCP fallback" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      sleep 250.milliseconds
      dns_response(query, truncated: true)
    end
    stub.serve_tcp do |query|
      sleep 900.milliseconds
      dns_response(query, answers: [a_answer])
    end

    expect_raises(IO::Error, /TCP fallback failed/) do
      udp_resolver(stub).query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 1.second) do
        raise "answer exceeded the attempt deadline"
      end
    end
  ensure
    stub.try(&.close)
  end
end

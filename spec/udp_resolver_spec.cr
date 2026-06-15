require "./spec_helper"

# A minimal in-process DNS server used to exercise the UDP resolver's transport
# behaviour (shared socket, response validation, retransmission, TCP fallback)
# without touching the network.
class DNSStub
  getter port : Int32
  getter source_ports = [] of Int32
  getter request_count = 0

  @tcp : TCPServer? = nil

  def initialize
    @udp = UDPSocket.new(Socket::Family::INET)
    @udp.bind("127.0.0.1", 0)
    @port = @udp.local_address.port
  end

  # handler: (query, request_count) -> response bytes, or nil to drop (loss)
  def serve_udp(&handler : DNS::Packet, Int32 -> Bytes?)
    spawn do
      buffer = Bytes.new(4096)
      loop do
        begin
          length, source = @udp.receive(buffer)
          @request_count += 1
          @source_ports << source.port
          query = DNS::Packet.from_slice(buffer[0, length].dup)
          if reply = handler.call(query, @request_count)
            @udp.send(reply, source)
          end
        rescue IO::Error
          break
        rescue ex
          # ignore malformed datagrams in tests
        end
      end
    end
  end

  def serve_tcp(&handler : DNS::Packet -> Bytes)
    server = TCPServer.new("127.0.0.1", @port)
    @tcp = server
    spawn do
      while client = server.accept?
        handle_tcp(client, handler)
      end
    rescue IO::Error
    end
  end

  private def handle_tcp(client, handler)
    length = client.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    bytes = Bytes.new(length)
    client.read_fully(bytes)
    query = DNS::Packet.from_slice(bytes)
    response = handler.call(query)

    io = IO::Memory.new
    io.write_bytes(response.size.to_u16, IO::ByteFormat::BigEndian)
    io.write response
    client.write io.to_slice
    client.flush
  ensure
    client.close
  end

  def close
    @udp.close
    @tcp.try(&.close)
  end
end

private def dns_response(
  query : DNS::Packet,
  *,
  truncated = false,
  answers = [] of DNS::Packet::ResourceRecord,
  id : UInt16? = nil,
  questions : Array(DNS::Packet::Question)? = nil,
) : Bytes
  DNS::Packet.new(
    id: id || query.id,
    response: true,
    truncation: truncated,
    questions: questions || query.questions,
    answers: answers,
  ).to_slice
end

private def a_answer(name = "example.com", ip = {93_u8, 184_u8, 216_u8, 34_u8})
  DNS::Packet::ResourceRecord.new(name, 1_u16, 1_u16, 60.seconds, resource_data: Bytes[ip[0], ip[1], ip[2], ip[3]])
end

private def udp_resolver(stub, *, timeout = 2.seconds, attempts = 1)
  resolver = DNS::Resolver::UDP.new(["127.0.0.1"], port: stub.port.to_u16)
  resolver.server_config = DNS::Servers.new(["127.0.0.1"], timeout: timeout, attempts: attempts)
  resolver
end

describe DNS::Resolver::UDP do
  it "resolves a query over the shared UDP socket" do
    stub = DNSStub.new
    stub.serve_udp { |query, _| dns_response(query, answers: [a_answer]) }
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
    stub.serve_udp { |query, _| dns_response(query, answers: [a_answer]) }
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
    stub.serve_udp { |query, _| dns_response(query, id: query.id &+ 1_u16, answers: [a_answer]) }
    resolver = udp_resolver(stub)

    expect_raises(IO::TimeoutError) do
      resolver.query("example.com", "127.0.0.1", {1_u16 => 1_u16}, 300.milliseconds) { |_| }
    end
  ensure
    stub.try(&.close)
  end

  it "ignores a response whose question does not match" do
    stub = DNSStub.new
    stub.serve_udp do |query, _|
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

  it "demultiplexes many concurrent queries over the shared socket" do
    stub = DNSStub.new
    stub.serve_udp { |query, _| dns_response(query, answers: [a_answer(query.questions.first.name)]) }
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
      asked, got = done.receive
      got.should eq asked # each fiber received its own response - no cross-talk
    end
  ensure
    stub.try(&.close)
  end

  it "retransmits and recovers when the first datagram is dropped" do
    stub = DNSStub.new
    # drop the first datagram, answer every retransmission
    stub.serve_udp { |query, count| count == 1 ? nil : dns_response(query, answers: [a_answer]) }

    resolver = DNS::Resolver::UDP.new(["127.0.0.1"], port: stub.port.to_u16)
    resolver.server_config = DNS::Servers.new(["127.0.0.1"], timeout: 1.second, attempts: 3)

    responses = [] of DNS::Packet
    resolver.select_server do |server, timeout|
      resolver.query("example.com", server, {1_u16 => 1_u16}, timeout) { |reply| responses << reply }
    end

    responses.size.should eq 1
    stub.request_count.should be >= 2 # proves a retransmission occurred


  ensure
    stub.try(&.close)
  end

  it "falls back to TCP when the UDP response is truncated" do
    stub = DNSStub.new
    stub.serve_udp { |query, _| dns_response(query, truncated: true) } # TC=1, no answers
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
end

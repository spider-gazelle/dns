require "./spec_helper"
require "./support/dns_stub"

describe Socket::Addrinfo do
  it "connects to a hostname resolved by the extension" do
    stub = DNSStub.new
    stub.serve_udp do |query, _, _|
      question = query.questions.first
      records = [] of DNS::Packet::ResourceRecord
      records << a_answer(question.name, {127_u8, 0_u8, 0_u8, 1_u8}) if question.type == DNS::RecordType::A.value
      dns_response(query, answers: records)
    end
    DNS.default_resolver = udp_resolver(stub)
    server = TCPServer.new("127.0.0.1", 0)

    client = TCPSocket.new("socket.test.", server.local_address.port)
    client.remote_address.address.should eq "127.0.0.1"
    stub.request_count.should be > 0
  ensure
    client.try(&.close)
    server.try(&.close)
    stub.try(&.close)
  end

  it "connects to numeric addresses without a DNS query" do
    server = TCPServer.new("127.0.0.1", 0)
    client = TCPSocket.new("127.0.0.1", server.local_address.port)
    client.remote_address.port.should eq server.local_address.port
  ensure
    client.try(&.close)
    server.try(&.close)
  end
end

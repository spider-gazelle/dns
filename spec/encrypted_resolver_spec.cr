require "http/server"
require "./spec_helper"
require "./support/dns_stub"

private def loopback_tls_contexts
  credentials = File.join(__DIR__, "support", "localhost.pem")
  server = OpenSSL::SSL::Context::Server.new
  server.certificate_chain = credentials
  server.private_key = credentials
  client = OpenSSL::SSL::Context::Client.new
  client.ca_certificates = credentials
  {server, client}
end

private def read_dns_frame(socket : IO)
  size = socket.read_bytes(UInt16, IO::ByteFormat::BigEndian)
  bytes = Bytes.new(size)
  socket.read_fully(bytes)
  DNS::Packet.from_slice(bytes)
end

private def write_dns_frame(socket : IO, response : Bytes)
  socket.write_bytes(response.size.to_u16, IO::ByteFormat::BigEndian)
  socket.write(response)
  socket.flush
end

describe DNS::Resolver::TLS do
  it "matches pipelined responses and ignores a duplicate and an unrelated question" do
    tcp = TCPServer.new("127.0.0.1", 0)
    server_context, client_context = loopback_tls_contexts
    options_seen = [] of DNS::Packet::EDNS::Option
    dnssec_flags_seen = [] of {Bool, Bool, Bool}
    spawn do
      client = tcp.accept
      client.read_timeout = 3.seconds
      OpenSSL::SSL::Socket::Server.open(client, server_context, sync_close: true) do |tls|
        a = read_dns_frame(tls)
        aaaa = read_dns_frame(tls)
        options_seen.concat(a.edns.try(&.options) || [] of DNS::Packet::EDNS::Option)
        options_seen.concat(aaaa.edns.try(&.options) || [] of DNS::Packet::EDNS::Option)
        [a, aaaa].each do |query|
          dnssec_flags_seen << {query.edns.try(&.dnssec_ok?) || false, query.authenticated_data?, query.checking_disabled?}
        end
        wrong = DNS::Packet::Question.new("other.test", 28_u16)
        write_dns_frame(tls, dns_response(aaaa, questions: [wrong], answers: [aaaa_answer("other.test")]))
        aaaa_reply = dns_response(aaaa, answers: [aaaa_answer("records.test")])
        write_dns_frame(tls, aaaa_reply)
        write_dns_frame(tls, aaaa_reply)
        write_dns_frame(tls, dns_response(a, answers: [a_answer("records.test")]))
      end
    rescue IO::Error | OpenSSL::Error
      # A client-side failure closes the fixture connection.
    end

    resolver = DNS::Resolver::TLS.new({"127.0.0.1" => "localhost"}, tcp.local_address.port.to_u16, tls_context: client_context)
    padding = DNS::Packet::EDNS::Option.new(12_u16, Bytes[0, 0])
    resolver.edns_options = [padding]
    responses = [] of DNS::Packet
    dnssec = DNS::DNSSEC::Options.new(dnssec_ok: true, request_ad: true)
    resolver.query("records.test", "127.0.0.1", {7_u16 => 1_u16, 8_u16 => 28_u16}, 3.seconds, dnssec: dnssec) { |packet| responses << packet }
    responses.map(&.id).should eq [8_u16, 7_u16]
    options_seen.should eq [padding, padding]
    dnssec_flags_seen.should eq [{true, true, false}, {true, true, false}]
    responses.flat_map(&.answers).map(&.ip_address.address).should eq ["2001:db8::1", "93.184.216.34"]
  ensure
    tcp.try(&.close)
  end
end

describe DNS::Resolver::HTTPS do
  it "bootstraps a named HTTPS endpoint through system DNS only while connecting" do
    server_context, client_context = loopback_tls_contexts
    dnssec_flags_seen = [] of {Bool, Bool, Bool}
    server = HTTP::Server.new do |context|
      body = context.request.body || raise "missing DNS request body"
      query = DNS::Packet.from_io(body)
      dnssec_flags_seen << {query.edns.try(&.dnssec_ok?) || false, query.authenticated_data?, query.checking_disabled?}
      context.response.content_type = "application/dns-message"
      context.response.write(dns_response(query, answers: [a_answer(query.questions.first.name)],
        additionals: [DNS::Packet::EDNS.new.to_resource_record], authenticated_data: true))
    end
    port = server.bind_tls("127.0.0.1", 0, server_context).port
    spawn { server.listen }

    hosts4 = DNS::Hosts.hosts[DNS::RecordType::A.value]
    hosts6 = DNS::Hosts.hosts[DNS::RecordType::AAAA.value]
    old4 = hosts4.delete("localhost")
    old6 = hosts6.delete("localhost")
    route = /\Alocalhost\z/i
    DNS.resolvers[route] = DNS::Resolver::UDP.new([] of String)

    endpoint = "https://localhost:#{port}/dns-query"
    DNS.default_resolver = DNS::Resolver::HTTPS.new([endpoint], tls_context: client_context)
    dnssec = DNS::DNSSEC::Options.new(dnssec_ok: true, request_ad: true, checking_disabled: true)
    packet = DNS.query_packet("records.test.", DNS::RecordType::A, dnssec: dnssec)
    packet.answers.map(&.ip_address.address).should eq ["93.184.216.34"]
    packet.authenticated_data?.should be_true
    dnssec_flags_seen.should eq [{true, true, true}]
    expect_raises(IO::Error, "no DNS servers configured") do
      Socket::Addrinfo.tcp("localhost", port)
    end
  ensure
    hosts4["localhost"] = old4 if hosts4 && old4
    hosts6["localhost"] = old6 if hosts6 && old6
    DNS.resolvers.delete(route) if route
    server.try(&.close)
  end

  it "correlates HTTP replies, rejects the wrong question, and remaps the DNS ID" do
    server_context, client_context = loopback_tls_contexts
    sizes = [] of UInt16
    server = HTTP::Server.new do |context|
      body = context.request.body || raise "missing DNS request body"
      query = DNS::Packet.from_io(body)
      if edns = query.edns
        sizes << edns.udp_payload_size
      end
      name = query.questions.first.name
      context.response.content_type = "application/dns-message; charset=binary"
      if name == "other.test"
        wrong = DNS::Packet::Question.new("records.test", 1_u16)
        context.response.write(dns_response(query, questions: [wrong], answers: [a_answer("records.test")]))
      else
        context.response.write(dns_response(query, answers: [a_answer(name)]))
      end
    end
    port = server.bind_tls("127.0.0.1", 0, server_context).port
    spawn { server.listen }

    endpoint = "https://127.0.0.1:#{port}/dns-query"
    resolver = DNS::Resolver::HTTPS.new([endpoint], tls_context: client_context)
    responses = [] of DNS::Packet
    resolver.query("records.test", endpoint, {42_u16 => 1_u16}, 3.seconds) { |packet| responses << packet }
    responses.map(&.id).should eq [42_u16]
    responses.first.answers.first.ip_address.address.should eq "93.184.216.34"
    expect_raises(DNS::Packet::ServerError, /does not match/) do
      resolver.query("other.test", endpoint, {43_u16 => 1_u16}, 3.seconds) { raise "unexpected answer" }
    end
    sizes.should eq [1232_u16, 1232_u16]
  ensure
    server.try(&.close)
  end
end

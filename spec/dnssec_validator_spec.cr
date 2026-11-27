require "json"
require "./spec_helper"
require "./support/dns_stub"

# Replay records independently signed and checked with dnspython/OpenSSL.
private class DNSSECFixture
  FIXTURE = JSON.parse(File.read(File.join(__DIR__, "support", "dnssec_validator.json")))
  NOW     = Time.unix(1_800_000_000)
  OPT     = DNS::Packet::EDNS.new.to_resource_record

  getter stub : DNSStub

  def initialize(@mode : Symbol = :normal)
    @stub = DNSStub.new
    @stub.serve_udp { |query, _, _| reply(query) }
  end

  def self.anchor(anchor_name = "anchor", *, sha384 = false) : DNS::DNSSEC::TrustAnchor
    row = FIXTURE[anchor_name].as_a
    digest = sha384 ? FIXTURE["anchor_sha384"] : row[4]
    DNS::DNSSEC::TrustAnchor.new(row[0].as_s, row[1].as_i.to_u16, row[2].as_i.to_u8, sha384 ? 4_u8 : row[3].as_i.to_u8, digest.as_s.hexbytes)
  end

  def validator(*, anchor_name = "anchor", sha384 = false) : DNS::DNSSEC::Validator
    validator_for([DNSSECFixture.anchor(anchor_name, sha384: sha384)])
  end

  def validator_for(anchors : Array(DNS::DNSSEC::TrustAnchor)) : DNS::DNSSEC::Validator
    DNS::DNSSEC::Validator.new(udp_resolver(stub), trust_anchors: anchors)
  end

  # Turns a fixture DS record into a configured trust anchor.
  def self.ds_anchor(query : String) : DNS::DNSSEC::TrustAnchor
    name, _, _, wire = FIXTURE["queries"][query][1][0].as_a
    data = wire.as_s.hexbytes
    DNS::DNSSEC::TrustAnchor.new(name.as_s, IO::ByteFormat::BigEndian.decode(UInt16, data[0, 2]), data[2], data[3], data[4..])
  end

  def close : Nil
    stub.close
  end

  private def reply(query : DNS::Packet) : Bytes
    question = query.questions.first
    key = "#{question.name}. #{question.type}"
    key = "self-ds-mutation" if @mode == :self_ds && key == "secure.test. 43"
    scenario = FIXTURE["queries"][key]?
    return dns_response(query, additionals: [OPT]) unless scenario

    code, raw_answers, raw_authorities = scenario.as_a
    answers = raw_answers.as_a.map { |row| record(row) }
    authorities = raw_authorities.as_a.map { |row| record(row) }
    if @mode == :tampered
      answers.map! do |answer|
        if answer.type == DNS::RecordType::A.value
          answer.resource_data = Bytes[192, 0, 2, 200]
        end
        answer
      end
    end
    authorities.clear if @mode == :missing_proof
    if @mode == :tampered_alias
      answers.map! do |answer|
        if answer.type == DNS::RecordType::CNAME.value
          answer.resource_data = "06666f7267656406736563757265047465737400".hexbytes
        end
        answer
      end
    end
    dns_response(query, answers: answers, authorities: authorities, additionals: [OPT],
      response_code: code.as_i.to_u8, authenticated_data: true)
  end

  private def record(raw : JSON::Any) : DNS::Packet::ResourceRecord
    name, type, ttl, wire = raw.as_a
    data = wire.as_s.hexbytes
    if name.as_s == "alias.secure.test." && type.as_i == DNS::RecordType::CNAME.value
      # The suffix begins at offset 18 in the echoed question.
      data = "06544152474554c012".hexbytes
    end
    DNS::Packet::ResourceRecord.new(name.as_s, type.as_i.to_u16, 1_u16, ttl.as_i.seconds, resource_data: data)
  end
end

describe DNS::Resolver::Validating do
  a_type = DNS::RecordType::A

  it "uses local validation for DNS.query and bypasses hosts, cache, and resolver routes" do
    fixture = DNSSECFixture.new
    upstream = udp_resolver(fixture.stub)
    upstream.server_config = DNS::Servers.new(upstream.servers, search: ["secure.test"], attempts: 1)
    DNS.default_resolver = DNS::Resolver::Validating.new(upstream, trust_anchors: [DNSSECFixture.anchor])

    name = "www.secure.test"
    route = /\Awww\.secure\.test\z/
    DNS.resolvers[route] = DNS::Resolver::UDP.new([] of String)
    DNS.cache.store(name, DNS::Packet.new(id: 0_u16, response: true, answers: [a_answer(name)]))
    DNS.query("www", [a_type]).map(&.ip_address.address).sort!.should eq ["192.0.2.3", "192.0.2.4"]

    expect_raises(DNS::DNSSEC::ValidationError) { DNS.query("localhost.", [a_type]) }
    error = expect_raises(DNS::DNSSEC::ValidationError) { DNS.query("127.0.0.1", [a_type]) }
    error.status.should eq DNS::DNSSEC::Status::Indeterminate
  ensure
    DNS.resolvers.delete(route) if route
    fixture.try(&.close)
  end

  it "rejects bogus and insecure replies, including bogus replies with upstream AD" do
    fixture = DNSSECFixture.new(:tampered)
    upstream = udp_resolver(fixture.stub)
    DNS.default_resolver = DNS::Resolver::Validating.new(upstream, trust_anchors: [DNSSECFixture.anchor])

    packet = DNS.query_packet("www.secure.test.", a_type)
    packet.authenticated_data?.should be_true
    error = expect_raises(DNS::DNSSEC::ValidationError) { DNS.query("www.secure.test.", [a_type]) }
    error.status.should eq DNS::DNSSEC::Status::Bogus

    error = expect_raises(DNS::DNSSEC::ValidationError) { DNS.query("host.unsigned.test.", [a_type]) }
    error.status.should eq DNS::DNSSEC::Status::Insecure
  ensure
    fixture.try(&.close)
  end

  it "preserves authenticated denials and validates all types before yielding records" do
    fixture = DNSSECFixture.new
    upstream = udp_resolver(fixture.stub)
    DNS.default_resolver = DNS::Resolver::Validating.new(upstream, trust_anchors: [DNSSECFixture.anchor])

    DNS.query("secure.test.", [DNS::RecordType::AAAA]).should be_empty
    expect_raises(DNS::Packet::NameError) { DNS.query("missing.secure.test.", [a_type]) }

    yielded = [] of DNS::Packet::ResourceRecord
    error = expect_raises(DNS::DNSSEC::ValidationError) do
      DNS.query("www.secure.test.", [a_type, DNS::RecordType::RRSIG]) { |record| yielded << record }
    end
    error.status.should eq DNS::DNSSEC::Status::Indeterminate
    yielded.should be_empty
  ensure
    fixture.try(&.close)
  end
end

describe DNS::DNSSEC::Validator do
  it "validates an RSA trust anchor, ECDSA delegation and RRset with its original signed TTL" do
    fixture = DNSSECFixture.new
    result = fixture.validator.query("WWW.Secure.Test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Secure
    result.secure?.should be_true
    result.answers.map(&.ip_address.address).sort!.should eq ["192.0.2.3", "192.0.2.4"]
    result.answers.map(&.ttl).uniq!.should eq [120.seconds]
  ensure
    fixture.try(&.close)
  end

  it "validates RSA-SHA512, P-384, Ed25519 and Ed448 signatures" do
    fixture = DNSSECFixture.new
    validator = fixture.validator(sha384: true)
    {"rsa512", "p384", "ed", "ed448"}.each do |name|
      result = validator.query("www.#{name}.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
      result.status.should eq DNS::DNSSEC::Status::Secure
    end
  ensure
    fixture.try(&.close)
  end

  it "rejects altered RDATA even when the upstream sends AD" do
    fixture = DNSSECFixture.new(:tampered)
    result = fixture.validator.query("www.secure.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Bogus
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "rejects expired signatures" do
    fixture = DNSSECFixture.new
    result = fixture.validator.query("www.secure.test.", DNS::RecordType::A, now: Time.unix(2_000_000_001))
    result.status.should eq DNS::DNSSEC::Status::Bogus
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "canonicalizes a compressed CNAME and validates the terminal RRset separately" do
    fixture = DNSSECFixture.new
    result = fixture.validator.query("alias.secure.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Secure
    result.answers.map(&.record_type).should eq [DNS::RecordType::CNAME, DNS::RecordType::A]
    result.answers.first.cname.should eq "target.secure.test"
    result.answers.last.ip_address.address.should eq "192.0.2.9"
  ensure
    fixture.try(&.close)
  end

  it "authenticates a synthesized CNAME against its signed DNAME" do
    fixture = DNSSECFixture.new
    result = fixture.validator.query("leaf.redirect.secure.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Secure
    result.answers.map(&.record_type).should eq [DNS::RecordType::DNAME, DNS::RecordType::CNAME, DNS::RecordType::A]
    result.answers.last.ip_address.address.should eq "192.0.2.66"
  ensure
    fixture.try(&.close)
  end

  it "rejects a synthesized CNAME that does not match the signed DNAME" do
    fixture = DNSSECFixture.new(:tampered_alias)
    result = fixture.validator.query("leaf.redirect.secure.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Bogus
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "requires a DS signature from the parent zone" do
    fixture = DNSSECFixture.new(:self_ds)
    result = fixture.validator.query("secure.test.", DNS::RecordType::DS, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Bogus
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "authenticates both NSEC and NSEC3 name errors" do
    fixture = DNSSECFixture.new
    validator = fixture.validator
    {"missing.secure.test.", "gone.secure.test."}.each do |name|
      result = validator.query(name, DNS::RecordType::A, now: DNSSECFixture::NOW)
      result.status.should eq DNS::DNSSEC::Status::Secure
      result.response_code.should eq 3_u16
      result.answers.should be_empty
    end
  ensure
    fixture.try(&.close)
  end

  it "authenticates NODATA and checks the wildcard expansion proof" do
    fixture = DNSSECFixture.new
    validator = fixture.validator
    denial = validator.query("secure.test.", DNS::RecordType::AAAA, now: DNSSECFixture::NOW)
    denial.status.should eq DNS::DNSSEC::Status::Secure
    denial.response_code.should eq 0_u16
    denial.answers.should be_empty

    wildcard = validator.query("wild.secure.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    wildcard.status.should eq DNS::DNSSEC::Status::Secure
    wildcard.answers.first.ip_address.address.should eq "192.0.2.55"
  ensure
    fixture.try(&.close)
  end

  it "rejects missing proofs for NXDOMAIN and wildcard expansion" do
    fixture = DNSSECFixture.new(:missing_proof)
    validator = fixture.validator
    {"missing.secure.test.", "wild.secure.test."}.each do |name|
      result = validator.query(name, DNS::RecordType::A, now: DNSSECFixture::NOW)
      result.status.should eq DNS::DNSSEC::Status::Bogus
      result.answers.should be_empty
    end
  ensure
    fixture.try(&.close)
  end

  it "authenticates wildcard NODATA using NSEC at the literal wildcard owner" do
    fixture = DNSSECFixture.new
    validator = fixture.validator(anchor_name: "anchor_wildcard")
    result = validator.query("unlisted.wildcard.test.", DNS::RecordType::AAAA, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Secure
    result.response_code.should eq 0_u16
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "distinguishes authenticated unsigned delegation from missing trust anchors" do
    fixture = DNSSECFixture.new
    validator = fixture.validator
    result = validator.query("host.unsigned.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Insecure
    result.answers.should be_empty

    result = validator.query("other.example.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Indeterminate
  ensure
    fixture.try(&.close)
  end

  it "classifies NSEC3 opt-out as insecure for both a delegation and a name error" do
    fixture = DNSSECFixture.new
    validator = fixture.validator
    {"host.optout.secure.test.", "optout-missing.secure.test."}.each do |name|
      result = validator.query(name, DNS::RecordType::A, now: DNSSECFixture::NOW)
      result.status.should eq DNS::DNSSEC::Status::Insecure
      result.answers.should be_empty
    end
  ensure
    fixture.try(&.close)
  end

  it "classifies a delegation with only unsupported DS algorithms as insecure" do
    fixture = DNSSECFixture.new
    result = fixture.validator(anchor_name: "anchor_algorithm").query("www.legacy.algorithm.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Insecure
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "classifies DNAME synthesis below an unsigned delegation as insecure" do
    fixture = DNSSECFixture.new
    result = fixture.validator.query("leaf.redirect.unsigned.test.", DNS::RecordType::A, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Insecure
    result.answers.should be_empty
  ensure
    fixture.try(&.close)
  end

  it "validates the DS RRset of a configured trust anchor through its parent" do
    fixture = DNSSECFixture.new
    anchors = [DNSSECFixture.anchor, DNSSECFixture.ds_anchor("secure.test. 43")]
    result = fixture.validator_for(anchors).query("secure.test.", DNS::RecordType::DS, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Secure
    result.answers.map(&.record_type).should eq [DNS::RecordType::DS]

    # Without an anchor above it, the DS RRset cannot be validated.
    result = fixture.validator_for(anchors[1..]).query("secure.test.", DNS::RecordType::DS, now: DNSSECFixture::NOW)
    result.status.should eq DNS::DNSSEC::Status::Indeterminate
  ensure
    fixture.try(&.close)
  end
end

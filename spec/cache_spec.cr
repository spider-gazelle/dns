require "./spec_helper"

class CacheResolver < DNS::Resolver
  def initialize
    @servers = ["127.0.0.1"]
    @server_config = DNS::Servers.new(@servers)
  end

  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    & : DNS::Packet ->
  )
    raise "should not perform query!"
  end
end

class TrackingCache < DNS::Cache::HashMap
  getter? closed = false

  def close : Nil
    @closed = true
    super
  end
end

private class LegacyCache
  include DNS::Cache

  @storage = DNS::Cache::HashMap.new

  def lookup(domain : String, query : UInt16) : DNS::Packet::ResourceRecord?
    @storage.lookup(domain, query)
  end

  def store(domain : String, result : DNS::Packet::ResourceRecord) : Nil
    @storage.store(domain, result)
  end

  def cleanup : Nil
    @storage.cleanup
  end

  def clear : Nil
    @storage.clear
  end

  def close : Nil
    @storage.close
  end
end

private def a_record(name : String, ip : String) : DNS::Packet::ResourceRecord
  DNS::Packet::ResourceRecord.new(name, DNS::RecordType::A.value, DNS::ClassCode::Internet.value, 60.seconds, DNS::Resource::A.new(ip))
end

private def cname_record(name : String, target : String, ttl : Time::Span) : DNS::Packet::ResourceRecord
  data = IO::Memory.new
  DNS::Resource.write_labels(data, target)
  resource = DNS::Resource::CNAME.new(data.to_slice, data.to_slice)
  DNS::Packet::ResourceRecord.new(name, DNS::RecordType::CNAME.value, 1_u16, ttl, resource)
end

# build an MX answer record with a parsed exchange target
private def mx_record(name : String, preference : Int, exchange : String) : DNS::Packet::ResourceRecord
  io = IO::Memory.new
  io.write_bytes(preference.to_u16, IO::ByteFormat::BigEndian)
  exchange.split('.').each do |label|
    io.write_byte(label.size.to_u8)
    io.write(label.to_slice)
  end
  io.write_byte(0_u8)
  data = io.to_slice
  DNS::Packet::ResourceRecord.new(name, DNS::RecordType::MX.value, DNS::ClassCode::Internet.value, 60.seconds, DNS::Resource::MX.new(data, data), data)
end

describe DNS::Cache::HashMap do
  it "closes a replaced cache without closing the active cache" do
    first = TrackingCache.new
    replacement = TrackingCache.new
    DNS.cache = first
    DNS.cache = replacement
    DNS.cache = replacement

    first.closed?.should be_true
    replacement.closed?.should be_false
  end

  it "returns the full answer set on a cache hit" do
    DNS.default_resolver = CacheResolver.new
    domain = "rrset.test"
    answers = [a_record(domain, "192.0.2.1"), a_record(domain, "192.0.2.2")]
    DNS.cache.store(domain, DNS::Packet.new(id: 0_u16, response: true, answers: answers))

    DNS.query(domain, [DNS::RecordType::A]).map(&.ip_address.address).should eq ["192.0.2.1", "192.0.2.2"]
    DNS.cache.lookup(domain, 1_u16).try(&.ip_address.address).should eq "192.0.2.1"
  end

  it "expires an address when any CNAME in its chain expires" do
    cache = DNS::Cache::HashMap.new
    alias_name = "alias.test"
    intermediate = "middle.test"
    canonical = "canonical.test"
    answers = [
      cname_record(alias_name, intermediate, 60.seconds),
      cname_record(intermediate, canonical, 125.milliseconds),
      a_record(canonical, "192.0.2.1"),
    ]
    cache.store(alias_name, DNS::Packet.new(id: 0_u16, response: true, answers: answers))
    cache.lookup(alias_name, DNS::RecordType::A.value).try(&.ttl).should eq 125.milliseconds
    answers.last.ttl.should eq 60.seconds

    sleep 150.milliseconds
    cache.lookup(alias_name, DNS::RecordType::A.value).should be_nil
  ensure
    cache.try(&.close)
  end

  it "supports custom caches that only implement the single-record interface" do
    DNS.default_resolver = CacheResolver.new
    DNS.cache = LegacyCache.new
    domain = "legacy-cache.test"
    answers = [a_record(domain, "192.0.2.1")]
    DNS.cache.store(domain, DNS::Packet.new(id: 0_u16, response: true, answers: answers))

    DNS.query(domain, [DNS::RecordType::A]).map(&.ip_address.address).should eq ["192.0.2.1"]
  end

  it "gives answers priority over additional records for the same name and type" do
    domain = "mail.example.test"
    additional = a_record(domain, "192.0.2.1")
    answer = a_record(domain, "192.0.2.2")
    glue_only = DNS::Packet.new(id: 1_u16, response: true, additionals: [additional])

    DNS.cache.store(domain, glue_only)
    DNS.cache.lookup(domain, 1_u16).try(&.ip_address.address).should eq "192.0.2.1"
    DNS.cache.store(domain, DNS::Packet.new(id: 2_u16, response: true, answers: [answer], additionals: [additional]))
    DNS.cache.store(domain, glue_only)
    DNS.cache.lookup(domain, 1_u16).try(&.ip_address.address).should eq "192.0.2.2"
  end

  it "should cache query results" do
    cache = DNS::Cache::HashMap.new
    DNS.cache = cache
    DNS.default_resolver = CacheResolver.new

    domain = "my.router"
    resource = DNS::Resource::A.new("192.168.0.1")
    resource_record = DNS::Packet::ResourceRecord.new(domain, resource.record_type, DNS::ClassCode::Internet.value, 200.milliseconds, resource)
    packet = DNS::Packet.new(id: 0_u16, response: true, answers: [resource_record])

    cache.store(domain, packet)

    # ensure queries are not sent
    expect_raises(Exception, "should not perform query!") do
      DNS.query("uncached.test", [DNS::RecordType::A])
    end

    response = DNS.query("my.router", [DNS::RecordType::A])
    response.size.should eq 1
    response.first.ip_address.address.should eq "192.168.0.1"

    sleep 300.milliseconds

    expect_raises(Exception, "should not perform query!") do
      DNS.query("my.router", [DNS::RecordType::A])
    end
  end

  it "never caches the EDNS0 OPT pseudo-record" do
    cache = DNS::Cache::HashMap.new
    domain = "example.com"

    a_record = DNS::Packet::ResourceRecord.new(domain, DNS::RecordType::A.value, DNS::ClassCode::Internet.value, 60.seconds, DNS::Resource::A.new("192.0.2.1"))
    # an OPT record as servers return it: type 41, CLASS = UDP size, non-zero TTL (DO bit)
    opt_record = DNS::Packet::ResourceRecord.new("", DNS::RecordType::OPT.value, 1232_u16, 32768.seconds)
    packet = DNS::Packet.new(id: 0_u16, response: true, answers: [a_record], additionals: [opt_record])

    cache.store(domain, packet)

    cache.lookup(domain, DNS::RecordType::A.value).should_not be_nil
    cache.lookup(domain, DNS::RecordType::OPT.value).should be_nil
  end

  it "caches additional records under their own name with a bailiwick check" do
    cache = DNS::Cache::HashMap.new

    mx = mx_record("proton.me", 10, "mail.protonmail.ch")
    glue = a_record("mail.protonmail.ch", "203.0.113.5") # referenced by the MX answer
    unrelated = a_record("evil.example", "198.51.100.9") # not referenced by any answer

    packet = DNS::Packet.new(
      id: 0_u16,
      response: true,
      questions: [DNS::Packet::Question.new("proton.me", DNS::RecordType::MX.value, DNS::ClassCode::Internet.value)],
      answers: [mx],
      additionals: [glue, unrelated],
    )
    cache.store("proton.me", packet)

    # the MX answer is cached against the queried name
    cache.lookup("proton.me", DNS::RecordType::MX.value).should_not be_nil

    # the glue A is cached under ITS OWN name, not under the queried name
    cache.lookup("proton.me", DNS::RecordType::A.value).should be_nil
    glue_hit = cache.lookup("mail.protonmail.ch", DNS::RecordType::A.value)
    glue_hit.should_not be_nil
    glue_hit.try(&.ip_address.address).should eq "203.0.113.5"

    # the unrelated additional is rejected by the bailiwick check
    cache.lookup("evil.example", DNS::RecordType::A.value).should be_nil
  end

  it "should cleanup and clear records" do
    cache = DNS::Cache::HashMap.new
    domain = "my.router"

    resource = DNS::Resource::A.new("192.168.0.1")
    a_record = DNS::Packet::ResourceRecord.new(domain, resource.record_type, DNS::ClassCode::Internet.value, 200.milliseconds, resource)
    resource = DNS::Resource::AAAA.new("2001:db8::1:0")
    aaaa_record = DNS::Packet::ResourceRecord.new(domain, resource.record_type, DNS::ClassCode::Internet.value, 50.milliseconds, resource)
    packet = DNS::Packet.new(id: 0_u16, response: true, answers: [a_record, aaaa_record])
    cache.store(domain, packet)

    sleep 51.milliseconds
    cache.@cache[domain].size.should eq 2
    cache.cleanup
    cache.@cache[domain].size.should eq 1
    cache.clear
    cache.@cache[domain].size.should eq 0
  end
end

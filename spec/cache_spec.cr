require "./spec_helper"

class CacheResolver < DNS::Resolver
  def initialize
    @servers = ["1.1.1.1"]
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

private def a_record(name : String, ip : String) : DNS::Packet::ResourceRecord
  DNS::Packet::ResourceRecord.new(name, DNS::RecordType::A.value, DNS::ClassCode::Internet.value, 60.seconds, DNS::Resource::A.new(ip))
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
      DNS.query("www.google.com", [DNS::RecordType::A])
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

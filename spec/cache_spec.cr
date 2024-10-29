require "./spec_helper"

class CacheResolver < DNS::Resolver
  def initialize
    @servers = ["1.1.1.1"]
  end

  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)
    raise "should not perform query!"
  end
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

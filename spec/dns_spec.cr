require "./spec_helper"

describe DNS do
  Spec.before_each do
    DNS.cache.clear
    DNS.default_resolver = DNS::Resolver::UDP.new
  end

  it "should parse DNS responses" do
    bytes1 = "f30c818000010001000000000377777706676f6f676c6503636f6d0000410001c00c0041000100004c3c000d00010000010006026832026833".hexbytes
    bytes2 = "cbf2818000010001000000000377777706676f6f676c6503636f6d0000410001c00c00410001000047ec000d00010000010006026832026833".hexbytes

    response1 = DNS::Packet.from_slice bytes1
    response2 = DNS::Packet.from_slice bytes2

    response1.answers.first.resource.as(DNS::Resource::HTTPS).alpn.should eq ["h2", "h3"]
    response2.answers.first.resource.as(DNS::Resource::HTTPS).alpn.should eq ["h2", "h3"]
  end

  it "queries google for A, AAAA and SVCB records" do
    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
        DNS::RecordType::HTTPS,
      ]
    )

    response.size.should eq 3
  end

  it "queries for MX records and caches additional IP addresses" do
    response = DNS.query(
      "proton.me",
      [
        DNS::RecordType::MX,
      ]
    )

    response.size.should eq 2
  end

  it "queries google using HTTPS resolver" do
    DNS.default_resolver = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
      ]
    )

    response.size.should eq 2
    response.map(&.ip_address).first.is_a?(Socket::IPAddress).should be_true
  end

  it "handles errors when returned from the server" do
    expect_raises(DNS::Packet::NameError, "querying ww1.notexisting12345.com for A") do
      DNS.query(
        "ww1.notexisting12345.com",
        [
          DNS::RecordType::A,
          DNS::RecordType::AAAA,
        ]
      )
    end
  end

  it "can perform IPv4 reverse lookups" do
    responses = DNS.query("gmail.com", [DNS::RecordType::A])
    ip = responses.find!(&.record_type.a?).ip_address

    reverse_domains = DNS.reverse_lookup ip
    reverse_domains.size.should be > 0
  end

  it "can perform IPv6 reverse lookups" do
    responses = DNS.query("gmail.com", [DNS::RecordType::AAAA])
    ip = responses.find!(&.record_type.aaaa?).ip_address

    reverse_domains = DNS.reverse_lookup ip
    reverse_domains.size.should be > 0
  end

  # note:: mDNS does not work in wsl on Windows
  # it does work when run as a windows application
  it "queries a .local service" do
    pending!("must have a service available locally on the network")

    response = DNS.query(
      "starling-home-hub.local",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
      ]
    )

    # Even though we only queried for A or AAAA the devices
    # would return both addresses for either query
    response.size.should eq 4
  end
end

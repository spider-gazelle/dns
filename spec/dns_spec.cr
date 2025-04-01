require "./spec_helper"

describe DNS do
  it "should select the appropriate resolver" do
    DNS.select_resolver("starling-home-hub.local").is_a?(DNS::Resolver::MDNS).should be_true
    DNS.select_resolver("www.google.com").is_a?(DNS::Resolver::UDP).should be_true
  end

  it "returns host file entries" do
    response = DNS.query("LocalHost", [DNS::RecordType::A])
    response.size.should eq 1
    response.first.ip_address.address.should eq "127.0.0.1"
  end

  it "queries for A, AAAA and SVCB records" do
    response = DNS.query(
      "www.microsoft.com",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
        DNS::RecordType::HTTPS,
      ]
    )

    response.size.should be >= 3
  end

  it "queries for MX records and caches additional IP addresses" do
    response = DNS.query("proton.me", [DNS::RecordType::MX])
    response.size.should eq 2
  end

  it "queries using HTTPS resolver" do
    DNS.default_resolver = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
      ]
    )

    response.size.should be >= 2
    response.map(&.ip_address).first.is_a?(Socket::IPAddress).should be_true
  end

  it "queries using TLS resolver" do
    DNS.default_resolver = DNS::Resolver::TLS.new({
      "8.8.8.8" => "dns.google",
    })

    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
      ]
    )

    response.size.should be >= 2
    response.map(&.ip_address).first.is_a?(Socket::IPAddress).should be_true
  end

  it "handles errors when returned from the server" do
    expect_raises(DNS::Packet::NameError, "Hostname lookup for ww1.notexisting12345.com failed") do
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
    responses = DNS.query("gmail.com", {DNS::RecordType::A})
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

  it "works with system addrinfo resolution" do
    DNS.default_resolver = DNS::Resolver::System.new

    # supported records
    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordType::A,
        DNS::RecordType::AAAA,
      ]
    )
    response.size.should be >= 2
    response.map(&.ip_address).first.is_a?(Socket::IPAddress).should be_true

    # compatible errors
    expect_raises(DNS::Packet::NameError, /Hostname lookup for ww1.notexisting12345.com failed/) do
      DNS.query(
        "ww1.notexisting12345.com",
        [
          DNS::RecordType::A,
          DNS::RecordType::AAAA,
        ]
      )
    end

    # fallback for other records
    response = DNS.query("proton.me", [DNS::RecordType::MX])
    response.size.should eq 2
  end
end

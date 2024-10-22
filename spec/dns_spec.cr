require "./spec_helper"

describe DNS do
  Spec.before_each do
    DNS.cache.clear
  end

  it "queries google for A, AAAA and SVCB records" do
    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordCode::A,
        DNS::RecordCode::AAAA,
        DNS::RecordCode::HTTPS,
      ]
    )

    response.size.should eq 3
  end

  it "queries google using HTTPS resolver" do
    DNS.default_resolver = DNS::Resolver::HTTPS.new(["https://1.1.1.1/dns-query"])

    response = DNS.query(
      "www.google.com",
      [
        DNS::RecordCode::A,
        DNS::RecordCode::AAAA,
        DNS::RecordCode::HTTPS,
      ]
    )

    response.size.should eq 3
  end

  it "should parse DNS responses" do
    bytes1 = "f30c818000010001000000000377777706676f6f676c6503636f6d0000410001c00c0041000100004c3c000d00010000010006026832026833".hexbytes
    bytes2 = "cbf2818000010001000000000377777706676f6f676c6503636f6d0000410001c00c00410001000047ec000d00010000010006026832026833".hexbytes

    response1 = DNS::Response.from_slice bytes1
    response2 = DNS::Response.from_slice bytes2

    response1.answers.first.payload.as(DNS::ResourceRecord::HTTPS).alpn.should eq response2.answers.first.payload.as(DNS::ResourceRecord::HTTPS).alpn
  end
end

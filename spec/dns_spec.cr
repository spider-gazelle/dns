require "./spec_helper"

describe DNS do
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
end

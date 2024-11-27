describe DNS::Hosts do
  it "should return entries defined in the system hosts file" do
    ip = DNS::Hosts.lookup("localhost", DNS::Resource::A::RECORD_TYPE).as(DNS::Packet::ResourceRecord).ip_address
    ip.address.should eq "127.0.0.1"

    ip = DNS::Hosts.lookup("localhost", DNS::Resource::AAAA::RECORD_TYPE).as(DNS::Packet::ResourceRecord).ip_address
    ip.address.should eq "::1"

    DNS::Hosts.lookup("unknown.dom", DNS::Resource::AAAA::RECORD_TYPE).should be_nil
  end
end

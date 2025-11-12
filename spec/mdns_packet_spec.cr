require "./spec_helper"

describe "mDNS Packet Parsing" do
  it "parses AirPlay mDNS response packet with compressed pointers" do
    # Real AirPlay mDNS packet that was causing "End of file reached" error
    # This packet contains DNS name compression (pointers) that span across
    # multiple sections of the packet, including pointers in the additional
    # records section that point back to earlier names in the packet.
    #
    # The bug was in resource.cr:46 where a UInt8 was shifted left by 8 bits,
    # causing overflow. For example, pointer 0xC1FC was incorrectly calculated
    # as offset 252 instead of 508 because (1 << 8) on a UInt8 overflows to 0.
    packet_hex = "0x00008400000000010000000a085f616972706c6179045f746370056c6f63616c00000c000100001194000c09546865204672616d65c00cc02b001080010000119401a70561636c3d301a64657669636569643d32433a39393a37353a37413a41443a34351b66656174757265733d30783746384144302c307833384243463436126665783d3049702f4145625069774e414341077273663d3078331866763d7032302e542d50544d44554142432d313330312e310661743d3078310b666c6167733d30783234340b6d6f64656c3d4c5330334412696e7465677261746f723d53616d73756e67146d616e7566616374757265723d53616d73756e671c73657269616c4e756d6265723d30544359334e4558353031323439420d70726f746f766572733d312e3111737263766572733d3337372e34302e30301470693d43453a45353a46313a41463a41393a3043287073693d30303030303030302d303030302d303030302d303030302d434545354631414641393043286769643d30303030303030302d303030302d303030302d303030302d434545354631414641393043066763676c3d3043706b3d33323630643462643363383933613161303939616661663239356533353463633330663239613530653933633861303134663264306633663637306466363863c02b00218001000000780012000000001b58096c6f63616c686f7374c01ac1fc00018001000000780004c0a80427c1fc001c80010000007800102403581161e200005d8a129b32126d58c1fc001c80010000007800102403581161e20000eaaacbfffeab5304c1fc001c8001000000780010fd2e6431846800015d8a129b32126d58c1fc001c8001000000780010fd2e643184680001eaaacbfffeab5304c1fc001c8001000000780010fe80000000000000eaaacbfffeab5304c02b002f8001000011940009c02b00050000800040c1fc002f8001000000780008c1fc000440000008"

    # Remove "0x" prefix and convert to bytes
    packet_hex = packet_hex.sub("0x", "")
    packet_data = Bytes.new(packet_hex.size // 2) do |i|
      packet_hex[i * 2, 2].to_u8(16)
    end

    # This should not raise "End of file reached" error
    packet = DNS::Packet.from_slice(packet_data)

    # Verify basic packet structure
    packet.response?.should be_true
    packet.authoritative_answer?.should be_true
    packet.questions.size.should eq 0
    packet.answers.size.should eq 1
    packet.additionals.size.should eq 10

    # Verify the answer record (PTR)
    answer = packet.answers.first
    answer.name.should eq "_airplay._tcp.local"
    answer.record_type.ptr?.should be_true
    answer.resource.as(DNS::Resource::PTR).domain_name.should eq "The Frame._airplay._tcp.local"

    # Verify the SRV record (additional record 2)
    srv_record = packet.additionals[1]
    srv_record.name.should eq "The Frame._airplay._tcp.local"
    srv_record.record_type.srv?.should be_true

    # Verify that A records using compressed pointers (0xC1FC) parse correctly
    # These records start at position 520 and use pointer 0xC1FC (offset 508)
    a_record = packet.additionals[2]
    a_record.record_type.a?.should be_true
    # The name should be resolved via the compressed pointer
    a_record.name.should_not be_empty
  end

  it "parses Kitchen device mDNS response packet with compressed pointers" do
    # Another real mDNS packet that was failing with "End of file reached" error
    # This packet contains device info, mesh networking info, and service discovery
    # records with DNS name compression pointers
    packet_hex = "0x000084000000000500000003074b69746368656e0c5f6465766963652d696e666f045f746370056c6f63616c000010000100001194000d0c6d6f64656c3d423632304150074b69746368656e085f6d657368636f70045f756470c0260010800100001194009b0472763d310d766e3d4170706c6520496e632e0f6d6e3d426f72646572526f75746572126e6e3d4d79486f6d653532343334343830300b78703d196bf241551449fd0874763d312e332e300b78613dc2673435f29f37c60b64643dc2673435f29f37c60773623d000001b10b61743d000066047d2d00000770743de76043110473713d620562623df0bf10646e3d44656661756c74446f6d61696e095f7365727669636573075f646e732d7364c055000c0001000011940002c04cc04c000c0001000011940002c044c0440021800100001194001000000000c001074b69746368656ec026c14100018001000011940004c0a8041ac141002f8001000011940008c141000440000008c044002f8001000011940009c04400050000800040"

    packet_hex = packet_hex.sub("0x", "")
    packet_data = Bytes.new(packet_hex.size // 2) do |i|
      packet_hex[i * 2, 2].to_u8(16)
    end

    # This should not raise "End of file reached" error
    packet = DNS::Packet.from_slice(packet_data)

    # Verify basic packet structure
    packet.response?.should be_true
    packet.authoritative_answer?.should be_true
    packet.questions.size.should eq 0
    packet.answers.size.should eq 5
    packet.additionals.size.should eq 3

    # Verify the first answer record (TXT record for device info)
    first_answer = packet.answers.first
    first_answer.name.should eq "Kitchen._device-info._tcp.local"
    first_answer.record_type.txt?.should be_true

    # Verify the mesh networking TXT record (second answer)
    mesh_answer = packet.answers[1]
    mesh_answer.name.should eq "Kitchen._meshcop._udp.local"
    mesh_answer.record_type.txt?.should be_true

    # Verify PTR records with compressed pointers
    ptr_record_1 = packet.answers[2]
    ptr_record_1.record_type.ptr?.should be_true
    ptr_record_1.name.should eq "_services._dns-sd._udp.local"

    ptr_record_2 = packet.answers[3]
    ptr_record_2.record_type.ptr?.should be_true
    ptr_record_2.name.should eq "_meshcop._udp.local"

    # Verify SRV record with compressed pointer
    srv_record = packet.answers[4]
    srv_record.record_type.srv?.should be_true
    srv_record.name.should eq "Kitchen._meshcop._udp.local"

    # Verify A record in additionals with compressed pointer
    a_record = packet.additionals[0]
    a_record.record_type.a?.should be_true
    a_record.name.should eq "Kitchen.local"
    a_record.ip_address.address.should eq "192.168.4.26"
  end
end

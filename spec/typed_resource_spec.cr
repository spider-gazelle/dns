require "./spec_helper"

# Wire vectors are encoded with dnspython 2.7.0 from the cases cited below.
private def decode_rdata(type : DNS::RecordType, hex : String) : DNS::Packet::ResourceRecord
  data = hex.hexbytes
  record = DNS::Packet::ResourceRecord.new("example.test", type.value, 1_u16, 60.seconds, resource_data: data)
  packet = DNS::Packet.new(id: 1_u16, response: true, answers: [record])
  decoded = DNS::Packet.from_slice(packet.to_slice).answers.first
  decoded.type.should eq type.value
  decoded.resource_data.should eq data
  decoded
end

describe DNS::Resource::CAA do
  it "preserves CAA flags and exposes the issuer-critical bit" do
    # Hickory DNS, test_reserved_flags_round_trip.
    # https://github.com/hickory-dns/hickory-dns/blob/97336fac7032d8d6b24ec1880696ec3267accf62/crates/proto/src/rr/rdata/caa.rs#L1210
    (0_u8..255_u8).each do |flags|
      wire = flags.to_s(16).rjust(2, '0') + "0569737375656578616d706c652e636f6d"
      caa = decode_rdata(DNS::RecordType::CAA, wire).resource.as(DNS::Resource::CAA)
      {caa.flags, caa.tag, caa.value}.should eq({flags, "issue", "example.com"})
      caa.issuer_critical?.should eq(flags >= 128)
    end
  end

  it "preserves mixed-case tags and arbitrary value bytes" do
    # dnspython, test_CAA_constructor_ascii_tag_roundtrip.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/test_rdata.py#L840
    caa = decode_rdata(DNS::RecordType::CAA, "0005495353554500ff63612e6578616d706c65").resource.as(DNS::Resource::CAA)
    caa.tag.should eq "ISSUE"
    caa.value.to_slice.hexstring.should eq "00ff63612e6578616d706c65"
    empty = decode_rdata(DNS::RecordType::CAA, "00056973737565").resource.as(DNS::Resource::CAA)
    empty.value.should be_empty
  end
end

describe DNS::Resource::TLSA do
  it "preserves unassigned algorithm field values in a certificate association" do
    # Hickory DNS, test_encode_decode_tlsa.
    # https://github.com/hickory-dns/hickory-dns/blob/97336fac7032d8d6b24ec1880696ec3267accf62/crates/proto/src/rr/rdata/tlsa.rs#L632
    tlsa = decode_rdata(DNS::RecordType::TLSA, "2827060102030405060708").resource.as(DNS::Resource::TLSA)
    {tlsa.certificate_usage, tlsa.selector, tlsa.matching_type}.should eq({40, 39, 6})
    tlsa.association_data.should eq Bytes[1, 2, 3, 4, 5, 6, 7, 8]
  end
end

describe DNS::Resource::SSHFP do
  it "decodes an RSA SHA-256 host fingerprint" do
    # miekg/dns, TestParseSSHFP.
    # https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/parse_test.go#L1433
    fingerprint = "bc6533cdc95a79078a39a56ea7635984ed655318ada9b6159e30723665da95bb"
    sshfp = decode_rdata(DNS::RecordType::SSHFP, "0102#{fingerprint}").resource.as(DNS::Resource::SSHFP)
    {sshfp.algorithm, sshfp.fingerprint_type}.should eq({1, 2})
    sshfp.fingerprint.hexstring.should eq fingerprint
  end
end

describe DNS::Resource::DS do
  it "decodes a DS digest and preserves algorithms outside the validator's support" do
    # miekg/dns, TestParseDS.
    # https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/parse_test.go#L394
    digest = "22261a8b0e0d799183e35e24e2ad6bb58533cba7e3b14d659e9ca09b2071398f"
    ds = decode_rdata(DNS::RecordType::DS, "9ef40c03#{digest}").resource.as(DNS::Resource::DS)
    {ds.key_tag, ds.algorithm, ds.digest_type}.should eq({40692, 12, 3})
    ds.digest.hexstring.should eq digest
  end
end

describe DNS::Resource::CDS do
  it "decodes a child's proposed DS and recognizes the deletion signal" do
    # dnspython, cds01 in the sample zone.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/example#L196
    digest = "123456789abcdef67890123456789abcdef67890"
    cds = decode_rdata(DNS::RecordType::CDS, "30390301#{digest}").resource.as(DNS::Resource::CDS)
    {cds.key_tag, cds.algorithm, cds.digest_type}.should eq({12345, 3, 1})
    cds.digest.hexstring.should eq digest
    cds.delete_signal?.should be_false

    deletion = decode_rdata(DNS::RecordType::CDS, "0000000000").resource.as(DNS::Resource::CDS)
    deletion.delete_signal?.should be_true
    {"0001000000", "0000000100", "0000000001", "000000000000"}.each do |wire|
      decode_rdata(DNS::RecordType::CDS, wire).resource.as(DNS::Resource::CDS).delete_signal?.should be_false
    end
  end
end

describe DNS::Resource::DNSKEY do
  it "decodes flags, protocol and algorithm and calculates the standard key tag" do
    # Hickory DNS, test_reserved_flags, with dnspython.dnssec.key_id as the tag oracle.
    # https://github.com/hickory-dns/hickory-dns/blob/97336fac7032d8d6b24ec1880696ec3267accf62/crates/proto/src/dnssec/rdata/dnskey.rs#L577
    key = decode_rdata(DNS::RecordType::DNSKEY, "ffff030800").resource.as(DNS::Resource::DNSKEY)
    {key.flags, key.protocol, key.algorithm, key.key_tag}.should eq({65535, 3, 8, 776})
    key.public_key.should eq Bytes[0]
    key.zone_key?.should be_true
    key.secure_entry_point?.should be_true
    key.revoked?.should be_true
  end

  it "uses the RSA/MD5 key tag rule for legacy keys" do
    # dnspython, dnskey02 in the sample zone.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/example#L185
    data = "010103010103050f9ada7330891d588ab4b621586cfc84c63d50646e9e22430730bbc34691cb3599ae23ba8b6a1d19659056e719a8a56c10d5bdd48396e2faae76780f66c6371af43fc5503cffba72163e9bec4b206bad33c865ba2c57bdafc9faa5a1eb946e688ea7f405aa874fef"
    key = decode_rdata(DNS::RecordType::DNSKEY, data).resource.as(DNS::Resource::DNSKEY)
    {key.flags, key.protocol, key.algorithm, key.key_tag}.should eq({257, 3, 1, 34639})
    key.revoked?.should be_false
  end
end

describe DNS::Resource::CDNSKEY do
  it "decodes a child's proposed key and recognizes the deletion signal" do
    key_data = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    key = decode_rdata(DNS::RecordType::CDNSKEY, "0101030f#{key_data}").resource.as(DNS::Resource::CDNSKEY)
    {key.flags, key.protocol, key.algorithm, key.key_tag}.should eq({257, 3, 15, 34259})
    key.public_key.hexstring.should eq key_data
    key.zone_key?.should be_true
    key.secure_entry_point?.should be_true
    key.revoked?.should be_false
    key.delete_signal?.should be_false

    # RFC 8078 Section 4 with verified errata 5049.
    # https://www.rfc-editor.org/rfc/inline-errata/rfc8078.html
    deletion = decode_rdata(DNS::RecordType::CDNSKEY, "0000030000").resource.as(DNS::Resource::CDNSKEY)
    deletion.delete_signal?.should be_true
    {"0001030000", "0000020000", "0000030001", "000003000000"}.each do |wire|
      decode_rdata(DNS::RecordType::CDNSKEY, wire).resource.as(DNS::Resource::CDNSKEY).delete_signal?.should be_false
    end
  end
end

describe DNS::Resource::RRSIG do
  it "decodes signature metadata and keeps the signature bytes" do
    # dnspython, rrsig01 in the sample zone.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/example#L176
    signature = "33115c6f2f64ff2bde74c7d080ace11f97abd0cbbfbc82f3e39224b2471e1468225829ff1b11e16a2e9502e1c0a0d533e18a14d6d55f4824aa4189fafffd7553a36577cd2311e0bc693acef8a2a609a6"
    rrsig = decode_rdata(DNS::RecordType::RRSIG, "002f010300000e105e0be1003e122f80085f03666f6f076578616d706c6500#{signature}").resource.as(DNS::Resource::RRSIG)
    {rrsig.type_covered, rrsig.algorithm, rrsig.labels, rrsig.original_ttl}.should eq({47, 1, 3, 3600})
    {rrsig.expiration, rrsig.inception, rrsig.key_tag}.should eq({1577836800, 1041379200, 2143})
    rrsig.signer_name.should eq "foo.example"
    rrsig.signature.hexstring.should eq signature
  end
end

describe DNS::Resource::NSEC3PARAM do
  it "decodes the hash parameters and keeps diagnostic flags" do
    # miekg/dns, TestNSEC.
    # https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/parse_test.go#L255
    params = decode_rdata(DNS::RecordType::NSEC3PARAM, "010000050830923c44c6cbbb8f").resource.as(DNS::Resource::NSEC3PARAM)
    {params.hash_algorithm, params.flags, params.iterations}.should eq({1, 0, 5})
    params.salt.hexstring.should eq "30923c44c6cbbb8f"

    unsalted = decode_rdata(DNS::RecordType::NSEC3PARAM, "0101000c00").resource.as(DNS::Resource::NSEC3PARAM)
    {unsalted.hash_algorithm, unsalted.flags, unsalted.iterations}.should eq({1, 1, 12})
    unsalted.salt.should be_empty
  end
end

describe DNS::Resource::HINFO do
  it "decodes binary character strings and the minimal ANY reply" do
    # Hickory DNS, test_binary.
    # https://github.com/hickory-dns/hickory-dns/blob/97336fac7032d8d6b24ec1880696ec3267accf62/crates/proto/src/rr/rdata/hinfo.rs#L219
    binary = decode_rdata(DNS::RecordType::HINFO, "0363707509000102030405060708").resource.as(DNS::Resource::HINFO)
    binary.cpu.should eq "cpu"
    binary.os.to_slice.should eq Bytes[0, 1, 2, 3, 4, 5, 6, 7, 8]

    minimal = decode_rdata(DNS::RecordType::HINFO, "075246433834383200").resource.as(DNS::Resource::HINFO)
    minimal.cpu.should eq "RFC8482"
    minimal.os.should be_empty
  end
end

describe DNS::Resource::NSEC do
  it "decodes multiple windows and preserves unknown type codes" do
    # dnspython, nsec01 and nsec03 in the sample zone.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/example#L178
    nsec = decode_rdata(DNS::RecordType::NSEC, "016106736563757265076578616d706c65000006400100000003041b000000000000000000000000000000000000000000000000000020").resource.as(DNS::Resource::NSEC)
    nsec.next_domain.should eq "a.secure.example"
    nsec.types.should eq Set{1_u16, 15_u16, 46_u16, 47_u16, 1234_u16}

    highest = decode_rdata(DNS::RecordType::NSEC, "000006000000000001ff200000000000000000000000000000000000000000000000000000000000000001").resource.as(DNS::Resource::NSEC)
    highest.next_domain.should be_empty
    highest.types.should eq Set{47_u16, 65535_u16}
  end
end

describe DNS::Resource::NSEC3 do
  it "decodes the hash, optional salt, opt-out flag and type windows" do
    # dnspython, nsec301 and nsec302 in the sample zone.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/example#L181
    tail = "14174eb2409fe28bcb4887a1836f957f0a8425e27b000722010000000290"
    {"04aabbccdd" => "aabbccdd", "00" => ""}.each do |encoded_salt, salt|
      nsec3 = decode_rdata(DNS::RecordType::NSEC3, "0101000c#{encoded_salt}#{tail}").resource.as(DNS::Resource::NSEC3)
      {nsec3.hash_algorithm, nsec3.flags, nsec3.iterations}.should eq({1, 1, 12})
      nsec3.opt_out?.should be_true
      nsec3.salt.hexstring.should eq salt
      nsec3.next_hash.hexstring.should eq "174eb2409fe28bcb4887a1836f957f0a8425e27b"
      nsec3.types.should eq Set{2_u16, 6_u16, 15_u16, 46_u16, 48_u16, 51_u16}
    end
    empty = decode_rdata(DNS::RecordType::NSEC3, "010000000001ff").resource.as(DNS::Resource::NSEC3)
    empty.opt_out?.should be_false
    empty.types.should be_empty
  end
end

describe DNS::Resource::NAPTR do
  it "decodes a SIP replacement and a rule with a regular expression" do
    # miekg/dns, TestPackNAPTR.
    # https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/dns_test.go#L128
    naptr = decode_rdata(DNS::RecordType::NAPTR, "00640032027365075349502b44325500045f736970045f756470056170706c6503636f6d00").resource.as(DNS::Resource::NAPTR)
    {naptr.order, naptr.preference, naptr.flags, naptr.service}.should eq({100, 50, "se", "SIP+D2U"})
    naptr.regexp.should be_empty
    naptr.replacement.should eq "_sip._udp.apple.com"

    regexp = decode_rdata(DNS::RecordType::NAPTR, "0064000a0175074532552b7369701c215e2e2a24217369703a696e666f406578616d706c652e746573742100").resource.as(DNS::Resource::NAPTR)
    regexp.replacement.should be_empty
    regexp.regexp.should eq "!^.*$!sip:info@example.test!"
  end
end

describe DNS::Resource::URI do
  it "decodes an endpoint URI with its priority and weight" do
    # miekg/dns, TestParseURI.
    # https://github.com/miekg/dns/blob/b2d6c9f4480a71247e0df4ce709122852a2849cf/parse_test.go#L1542
    uri = decode_rdata(DNS::RecordType::URI, "000a0001687474703a2f2f7777772e6578616d706c652e636f6d2f70617468").resource.as(DNS::Resource::URI)
    {uri.priority, uri.weight, uri.target}.should eq({10, 1, "http://www.example.com/path"})
  end
end

describe DNS::Packet::ResourceRecord do
  it "retains malformed RDATA for diagnostics without decoding it" do
    # dnspython, test_empty_trailing_field_wire and test_bad_URI_wire.
    # https://github.com/rthalley/dnspython/blob/095a30eee6f9128eec540a4af27fb1872d4307da/tests/test_rdata.py#L991
    {
      {DNS::RecordType::CAA, "0000"},
      {DNS::RecordType::CAA, "0005612d62"},
      {DNS::RecordType::CAA, "0003612d62"},
      {DNS::RecordType::DS, "00010dfe"},
      {DNS::RecordType::DNSKEY, "0100030d"},
      {DNS::RecordType::RRSIG, "00010d0200000e105f5e10005f5e0000000100"},
      {DNS::RecordType::TLSA, "030100"},
      {DNS::RecordType::SSHFP, "04fe"},
      {DNS::RecordType::URI, "000a0001"},
      {DNS::RecordType::NAPTR, "00080010012d000000"},
      {DNS::RecordType::NAPTR, "0008001000000178016100"},
      {DNS::RecordType::NSEC3, "0100000104aabb"},
      {DNS::RecordType::CDS, "00000000"},
      {DNS::RecordType::CDNSKEY, "00000300"},
      {DNS::RecordType::NSEC3PARAM, "010000050830923c"},
      {DNS::RecordType::NSEC3PARAM, "0100000500ff"},
      {DNS::RecordType::HINFO, "03637075046f73"},
      {DNS::RecordType::HINFO, "03637075"},
      {DNS::RecordType::HINFO, "03637075026f7300"},
    }.each do |type, raw|
      decode_rdata(type, raw).resource.should be_nil
    end
  end

  it "rejects forbidden compression and malformed denial bitmaps" do
    {
      {DNS::RecordType::RRSIG, "00010d0200000e105f5e10005f5e00000001c00c01"},
      {DNS::RecordType::NSEC, "c00c000140"},
      {DNS::RecordType::NAPTR, "00080010000000c00c"},
      {DNS::RecordType::NAPTR, "000800100000000001"},
      {DNS::RecordType::NSEC, "00"},
      {DNS::RecordType::NSEC, "0000024000"},
      {DNS::RecordType::NSEC, "00000140000120"},
      {DNS::RecordType::NSEC3, "010000000001ff000240"},
    }.each do |type, raw|
      decode_rdata(type, raw).resource.should be_nil
    end
  end
end

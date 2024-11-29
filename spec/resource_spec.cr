require "./spec_helper"

# bytes and values extracted from various WireShark captures
describe DNS::Resource do
  it "should parse a A response" do
    bytes = "75c08180000100010000000003777777066e6574627364036f72670000010001c00c00010001000140ef0004cc98be0c".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "www.netbsd.org"
    response.answers.first.ttl.should eq(22.hours + 49.minutes + 19.seconds)
    response.answers.first.resource.as(DNS::Resource::A).address.should eq "204.152.190.12"
  end

  it "should parse a AAAA response" do
    bytes = "f0d48180000100010000000003777777066e6574627364036f726700001c0001c00c001c0001000151800010200104f80004000702e081fffe529a6b".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "www.netbsd.org"
    response.answers.first.ttl.should eq 1.day
    response.answers.first.resource.as(DNS::Resource::AAAA).address.should eq "2001:4f8:4:7:2e0:81ff:fe52:9a6b"
  end

  it "should parse a HTTPS response" do
    bytes1 = "f30c818000010001000000000377777706676f6f676c6503636f6d0000410001c00c0041000100004c3c000d00010000010006026832026833".hexbytes
    bytes2 = "cbf2818000010001000000000377777706676f6f676c6503636f6d0000410001c00c00410001000047ec000d00010000010006026832026833".hexbytes

    response1 = DNS::Packet.from_slice bytes1
    response2 = DNS::Packet.from_slice bytes2

    response1.answers.first.resource.as(DNS::Resource::HTTPS).alpn.should eq ["h2", "h3"]
    response2.answers.first.resource.as(DNS::Resource::HTTPS).alpn.should eq ["h2", "h3"]
  end

  it "should parse a PTR response" do
    bytes = "5a53858000010001000000000131013001300331323707696e2d61646472046172706100000c0001c00c000c000100000e10000b096c6f63616c686f737400".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "1.0.0.127.in-addr.arpa"
    response.answers.first.ttl.should eq 1.hour
    response.answers.first.resource.as(DNS::Resource::PTR).domain_name.should eq "localhost"
  end

  it "should parse a NS response" do
    bytes = "208a8180000100040000000003697363036f72670000020001c00c0002000100000e10000e066e732d657874046e727431c00cc00c0002000100000e10000e066e732d6578740473746831c00cc00c0002000100000e100009066e732d657874c00cc00c0002000100000e10000e066e732d657874046c676131c00c".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "isc.org"
    response.answers.size.should eq 4
    response.answers.first.ttl.should eq 1.hour
    response.answers[0].resource.as(DNS::Resource::NS).name_server.should eq "ns-ext.nrt1.isc.org"
    response.answers[1].resource.as(DNS::Resource::NS).name_server.should eq "ns-ext.sth1.isc.org"
    response.answers[2].resource.as(DNS::Resource::NS).name_server.should eq "ns-ext.isc.org"
    response.answers[3].resource.as(DNS::Resource::NS).name_server.should eq "ns-ext.lga1.isc.org"
  end

  it "should parse a TX response" do
    bytes = "10328180000100010000000006676f6f676c6503636f6d0000100001c00c001000010000010e00100f763d7370663120707472203f616c6c".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "google.com"
    response.answers.first.ttl.should eq(4.minutes + 30.seconds)
    response.answers.first.resource.as(DNS::Resource::TXT).text_data.should eq ["v=spf1 ptr ?all"]
  end

  it "should parse a MX response" do
    bytes = "f76f8180000100060000000606676f6f676c6503636f6d00000f0001c00c000f000100000228000a002805736d747034c00cc00c000f000100000228000a000a05736d747035c00cc00c000f000100000228000a000a05736d747036c00cc00c000f000100000228000a000a05736d747031c00cc00c000f000100000228000a000a05736d747032c00cc00c000f000100000228000a002805736d747033c00cc02a00010001000002580004d8ef251ac0400001000100000258000440e9a719c0560001000100000258000442660919c06c00010001000002580004d8ef3919c08200010001000002580004d8ef2519c09800010001000002580004d8ef391a".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "google.com"
    response.answers.first.ttl.should eq(9.minutes + 12.seconds)

    response.answers[0].resource.as(DNS::Resource::MX).preference.should eq 40
    response.answers[1].resource.as(DNS::Resource::MX).preference.should eq 10
    response.answers[2].resource.as(DNS::Resource::MX).preference.should eq 10
    response.answers[3].resource.as(DNS::Resource::MX).preference.should eq 10
    response.answers[4].resource.as(DNS::Resource::MX).preference.should eq 10
    response.answers[5].resource.as(DNS::Resource::MX).preference.should eq 40

    response.answers[0].resource.as(DNS::Resource::MX).exchange.should eq "smtp4.google.com"
    response.answers[1].resource.as(DNS::Resource::MX).exchange.should eq "smtp5.google.com"
    response.answers[2].resource.as(DNS::Resource::MX).exchange.should eq "smtp6.google.com"
    response.answers[3].resource.as(DNS::Resource::MX).exchange.should eq "smtp1.google.com"
    response.answers[4].resource.as(DNS::Resource::MX).exchange.should eq "smtp2.google.com"
    response.answers[5].resource.as(DNS::Resource::MX).exchange.should eq "smtp3.google.com"

    response.additionals[0].resource.as(DNS::Resource::A).address.should eq "216.239.37.26"
    response.additionals[1].resource.as(DNS::Resource::A).address.should eq "64.233.167.25"
    response.additionals[2].resource.as(DNS::Resource::A).address.should eq "66.102.9.25"
    response.additionals[3].resource.as(DNS::Resource::A).address.should eq "216.239.57.25"
    response.additionals[4].resource.as(DNS::Resource::A).address.should eq "216.239.37.25"
    response.additionals[5].resource.as(DNS::Resource::A).address.should eq "216.239.57.26"
  end

  it "should parse a CNAME response" do
    bytes = "7e5b8180000100060008000709777777696d616765730561646f626503636f6d0000010001c00c000500010000002d001109777777696d616765730477697034c016c03100050001000001d2002309777777696d616765730561646f626503636f6d09656467657375697465036e657400c04e0005000100002104003709777777696d616765730561646f626503636f6d09656467657375697465036e65740b676c6f62616c726564697206616b61646e73c06cc07d00050001000001d20011056131393533017806616b616d6169c06cc0c0000100010000000c000496c76468c0c0000100010000000c000496c76465c0c600020001000041010006036e3478c0c8c0c600020001000041010006036e3178c0c8c0c600020001000041010006036e3778c0c8c0c600020001000041010006036e3078c0c8c0c600020001000041010006036e3378c0c8c0c600020001000041010006036e3578c0c8c0c600020001000041010006036e3678c0c8c0c600020001000041010006036e3278c0c8c1330001000100003e7e000496c7646bc10f00010001000013320004d89ce11ec17b0001000100003cfa0004d1aa752ec14500010001000043730004d1aa752ec0fd0001000100001332000496c700e3c1570001000100003cfa000496c76462c1690001000100003e7c000496c76462".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "wwwimages.adobe.com"
    response.answers.first.ttl.should eq 45.seconds

    response.answers[0].resource.as(DNS::Resource::CNAME).target.should eq "wwwimages.wip4.adobe.com"
    response.answers[1].resource.as(DNS::Resource::CNAME).target.should eq "wwwimages.adobe.com.edgesuite.net"
    response.answers[2].resource.as(DNS::Resource::CNAME).target.should eq "wwwimages.adobe.com.edgesuite.net.globalredir.akadns.net"
    response.answers[3].resource.as(DNS::Resource::CNAME).target.should eq "a1953.x.akamai.net"
    response.answers[4].resource.as(DNS::Resource::A).address.should eq "150.199.100.104"
    response.answers[5].resource.as(DNS::Resource::A).address.should eq "150.199.100.101"

    response.authorities[0].name.should eq "x.akamai.net"
    response.authorities[1].name.should eq "x.akamai.net"
    response.authorities[2].name.should eq "x.akamai.net"
    response.authorities[3].name.should eq "x.akamai.net"
    response.authorities[4].name.should eq "x.akamai.net"
    response.authorities[5].name.should eq "x.akamai.net"
    response.authorities[6].name.should eq "x.akamai.net"
    response.authorities[7].name.should eq "x.akamai.net"

    response.authorities[0].resource.as(DNS::Resource::NS).name_server.should eq "n4x.akamai.net"
    response.authorities[1].resource.as(DNS::Resource::NS).name_server.should eq "n1x.akamai.net"
    response.authorities[2].resource.as(DNS::Resource::NS).name_server.should eq "n7x.akamai.net"
    response.authorities[3].resource.as(DNS::Resource::NS).name_server.should eq "n0x.akamai.net"
    response.authorities[4].resource.as(DNS::Resource::NS).name_server.should eq "n3x.akamai.net"
    response.authorities[5].resource.as(DNS::Resource::NS).name_server.should eq "n5x.akamai.net"
    response.authorities[6].resource.as(DNS::Resource::NS).name_server.should eq "n6x.akamai.net"
    response.authorities[7].resource.as(DNS::Resource::NS).name_server.should eq "n2x.akamai.net"

    response.additionals[0].resource.as(DNS::Resource::A).address.should eq "150.199.100.107"
    response.additionals[1].resource.as(DNS::Resource::A).address.should eq "216.156.225.30"
    response.additionals[2].resource.as(DNS::Resource::A).address.should eq "209.170.117.46"
    response.additionals[3].resource.as(DNS::Resource::A).address.should eq "209.170.117.46"
    response.additionals[4].resource.as(DNS::Resource::A).address.should eq "150.199.0.227"
    response.additionals[5].resource.as(DNS::Resource::A).address.should eq "150.199.100.98"
    response.additionals[6].resource.as(DNS::Resource::A).address.should eq "150.199.100.98"
  end

  it "should parse a SOA response" do
    bytes = "dbef818000010000000100000b797366696f6a6c66647a6203636f6d0000010001c0180006000100000338003d01610c67746c642d73657276657273036e657400056e73746c640c766572697369676e2d677273c01850a66002000007080000038400093a8000015180".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "ysfiojlfdzb.com"
    response.authorities.first.ttl.should eq(13.minutes + 44.seconds)
    soa = response.authorities.first.resource.as(DNS::Resource::SOA)
    soa.primary_ns.should eq "a.gtld-servers.net"
    soa.admin_email.should eq "nstld@verisign-grs.com"
    soa.serial.should eq 1353080834_u32

    soa.refresh.should eq 30.minutes
    soa.retry.should eq 15.minutes
    soa.expire.should eq 7.days
    soa.minimum_ttl.should eq 1.day
  end

  it "should parse a SRV response" do
    bytes = "d0ad85800001000200000000055f6c646170045f74637003706463065f6d736463730977656175626c656175036b3132026d6f0275730000210001c00c002100010000038400120000006401850977732d736572766572c022c00c0021000100000384000c00000064018503667331c022".hexbytes
    response = DNS::Packet.from_slice bytes

    response.questions.first.name.should eq "_ldap._tcp.pdc._msdcs.weaubleau.k12.mo.us"
    response.answers.first.ttl.should eq 15.minutes

    srv = response.answers.first.resource.as(DNS::Resource::SRV)
    srv.priority.should eq 0
    srv.weight.should eq 100
    srv.port.should eq 389
    srv.target.should eq "ws-server.weaubleau.k12.mo.us"

    srv = response.answers.last.resource.as(DNS::Resource::SRV)
    srv.priority.should eq 0
    srv.weight.should eq 100
    srv.port.should eq 389
    srv.target.should eq "fs1.weaubleau.k12.mo.us"
  end

  it "should parse a response where we don't have resource parsers" do
    bytes = "dbf884130001000000060001055f6c646170045f7463701744656661756c742d46697273742d536974652d4e616d65065f7369746573026463065f6d736463730777326b33646f6d036b766d07707269766174650000210001000006000100015180004001610c726f6f742d73657276657273036e657400056e73746c640c766572697369676e2d67727303636f6d0077ee12dd000007080000038400093a800001518000002e000100015180009300060800000151805057b980504e70f0c4de00afd1ff0fc71fdd6ec68a8d4347a64610bd8137fcbcda9b913aaa0168e0b69f1063b292da073af61a00fe7b623740065094a9850e9a1abaf04a4ae86da66a140b8452a7b9b7a83e996dd2ae24fd6a21a5287321fe3b7a0a1ae8ff1723a6b25c1127d32f4b078cd0e4468014d3e5f848380d0521557ce0386310b5c2da4f24d4f100002f000100015180000d0261630000072200000000038000002e0001000151800093002f0800000151805057b980504e70f0c4de0030bcf72ed1345d3f7c63ec3750c585306c4427ece513fc2d3307de250ff28cb1a37bedcbdfb556f84f79caa8868f85246be5211de8123bb1d6ddb5e03bff65c76c029a57449097e5bdc39bb34e1e29c9144245e21604c739688ae0aa2392f39cc09bb51c274954cdca1066fd712d494dbbfb9741086722b1e9b2c29a6ab3e73e02707200002f000100015180000d0370726f000006200000000013c1f8002e0001000151800093002f0801000151805057b980504e70f0c4de0060103fc6b50c984f7a5c14a8d95cb66f727c6a0d05c5254b2bbcdae214dea37beb79dc49b5327a2527249a9e3bd7a804b966f673702c8fe9ecdae208fbb1ab59da9f8ac7d9d8ab1aaea7181c0588a1c593952c575f91bb335b5b8c6d5b114b05f19c0902c220b16c36e0542a6889fb77f3daf6f96ac5704539605f647d7a62250000290200000080000000".hexbytes
    response = DNS::Packet.from_slice bytes
    response.questions.first.name.should eq "_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.w2k3dom.kvm.private"
    response.authorities.size.should eq 6
    response.additionals.size.should eq 1
  end
end

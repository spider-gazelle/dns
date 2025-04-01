require "log"

# An extensible DNS implementation that doesn't block the event loop
module DNS
  Log = ::Log.for(self)

  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  class_property timeout : Time::Span = 1.second
  class_property cache : Cache { Cache::HashMap.new }
  class_property default_resolver : Resolver { Resolver::UDP.new }
  class_getter resolvers : Hash(Regex, Resolver) = Hash(Regex, Resolver){
    /.+\.local$/i => Resolver::MDNS.new,
  }

  # Specifies the kind of query in this message.
  enum OpCode : UInt8
    QUERY  = 0 # a standard query
    IQUERY = 1 # an inverse query, deprecated, use PTR instead
    STATUS = 2 # a server status request
  end

  enum ClassCode : UInt16
    Internet =   1
    Chaos    =   3 # Chaosnet developed at MIT in the 1970s for their AI Lab
    Hesiod   =   4 # MIT's Athena project
    NONE     = 254 # used to indicate that a specific record should be deleted
    ANY      = 255 # retrieves all the available record types for a given name
  end

  enum RecordType : UInt16
    A          =     1 # Maps a domain name to an IPv4 address
    NS         =     2 # Name Server record, indicates authoritative DNS servers for the domain
    CNAME      =     5 # Canonical Name record, aliases one domain name to another
    SOA        =     6 # Start of Authority record, contains administrative information about the zone
    PTR        =    12 # Pointer record, used for reverse DNS lookups (IP to domain name)
    MX         =    15 # Mail Exchanger record, specifies mail servers responsible for receiving email
    TXT        =    16 # Text record, holds arbitrary text; often used for domain verification and policies like SPF
    RP         =    17 # Responsible Person record, provides email address of the person responsible for the domain
    AFSDB      =    18 # AFS Database record, points to a server that hosts an AFS (Andrew File System) database
    X25        =    19 # X.25 address mapping
    ISDN       =    20 # ISDN address mapping
    RT         =    21 # Route Through record, specifies a preferred route for communication
    NSAP       =    22 # NSAP Address record, maps domain names to NSAP addresses
    SIG        =    24 # Signature record, part of early DNSSEC (replaced by RRSIG)
    KEY        =    25 # Key record, used to store public keys (replaced by DNSKEY in DNSSEC)
    AAAA       =    28 # Maps a domain name to an IPv6 address
    LOC        =    29 # Location record, specifies geographical location of the domain
    SRV        =    33 # Service Locator record, specifies a host and port for specific services (e.g., SIP, XMPP)
    ATMA       =    34 # ATM Address record, maps domain names to Asynchronous Transfer Mode (ATM) addresses
    NAPTR      =    35 # Naming Authority Pointer record, used for regular expression-based rewrite rules for URIs
    KX         =    36 # Key Exchanger record, specifies a key exchange mechanism for the domain
    CERT       =    37 # Certificate record, stores public key certificates
    DNAME      =    39 # Delegation Name record, aliases an entire subtree of the domain name space to another domain
    OPT        =    41 # Option record, used to support EDNS(0) extensions to the DNS protocol
    APL        =    42 # Address Prefix List record, specifies lists of address ranges
    DS         =    43 # Delegation Signer record, used in DNSSEC to establish a chain of trust
    SSHFP      =    44 # SSH Fingerprint record, stores SSH key fingerprints for authentication
    IPSECKEY   =    45 # IPsec Key record, stores public keys for IPsec
    RRSIG      =    46 # Resource Record Signature, contains the DNSSEC signature for a set of DNS records
    NSEC       =    47 # Next Secure record, used in DNSSEC to prove the non-existence of a domain name
    DNSKEY     =    48 # DNS Public Key record, stores public keys used in DNSSEC
    DHCID      =    49 # DHCP Identifier record, used for DHCP clients in dynamic DNS updates
    NSEC3      =    50 # Hashed Next Secure record, used to prevent zone enumeration in DNSSEC
    NSEC3PARAM =    51 # NSEC3 Parameters record, provides parameters for the NSEC3 record in DNSSEC
    TLSA       =    52 # TLS Authentication record, used to associate TLS certificates with domain names
    SMIMEA     =    53 # S/MIME Association record, used to associate S/MIME certificates with email addresses
    HIP        =    55 # Host Identity Protocol record, used to store Host Identity Tags
    CDS        =    59 # Child Delegation Signer record, used in DNSSEC for key management automation
    CDNSKEY    =    60 # Child DNSKEY record, used in DNSSEC for automated key management
    OPENPGPKEY =    61 # OpenPGP Key record, stores OpenPGP public keys for email encryption
    CSYNC      =    62 # Child-to-Parent Synchronization record, used to sync records between child and parent zones
    SVCB       =    64 # Service Binding record, used to bind a domain name to a specific service
    HTTPS      =    65 # HTTPS Service record, a special version of SVCB for HTTPS services
    EUI48      =   108 # EUI-48 address record, stores a 48-bit Extended Unique Identifier
    EUI64      =   109 # EUI-64 address record, stores a 64-bit Extended Unique Identifier
    URI        =   256 # Uniform Resource Identifier record, maps domain names to URIs
    CAA        =   257 # Certification Authority Authorization record, specifies which CAs can issue certificates for the domain
    TA         = 32768 # Trust Anchor record, used in DNSSEC for static trust anchors (experimental)
    DLV        = 32769 # DNSSEC Lookaside Validation record, used to validate DNSSEC without full chain of trust (deprecated)
  end

  # finds the first matching resolver for the domain provided
  def self.select_resolver(domain : String) : Resolver
    resolver = default_resolver
    resolvers.each do |regex, res|
      if regex =~ domain
        resolver = res
        break
      end
    end
    resolver
  end

  # query the DNS records of a domain and return the answers
  #
  # NOTE:: A or AAAA answers may include cname and other records that are not directly relevent to the query.
  # It is up to the consumer to filter for the relevant results
  def self.query(domain : String, query_records : Enumerable(RecordType | UInt16), &) : Nil
    # RFC 3986 says:
    # > When a non-ASCII registered name represents an internationalized domain name
    # > intended for resolution via the DNS, the name must be transformed to the IDNA
    # > encoding [RFC3490] prior to name lookup.
    domain = URI::Punycode.to_ascii domain.downcase
    query_records = query_records.map { |query| query.is_a?(RecordType) ? query.value : query }.to_set
    queries_to_send = {} of UInt16 => UInt16

    # check hosts file + cache and collect the queries we need to transmit
    cache_local = cache
    query_records.each do |record|
      if cached_record = Hosts.lookup(domain, record) || cache_local.lookup(domain, record)
        yield cached_record
        next
      end

      # find a unique id for this request
      query_id = rand(UInt16::MAX)
      loop do
        break if queries_to_send[query_id]?.nil?
        query_id = rand(UInt16::MAX)
      end
      queries_to_send[query_id] = record
    end

    # return if all queries are answered from cache
    return if queries_to_send.empty?

    # select a resolver for this domain (i.e. mDNS for .local domains)
    resolver = select_resolver(domain)

    # Track which questions have been answered so far
    questions_answered = Array(UInt16).new(queries_to_send.size)

    # query the server
    resolver.select_server do |dns_server|
      queries_to_send.reject!(questions_answered)

      Log.trace { "Querying #{dns_server} -- domain: #{domain.inspect}, records: #{queries_to_send.values}" }
      resolver.query(domain, dns_server, queries_to_send) do |response|
        # raise any errors,
        # ServerError will be handled by moving to the next DNS server, assuming there is one
        # other errors indicate an issue with the request and will be propagated
        response.raise_on_error!
        questions_answered << response.id
        cache_local.store(domain, response) rescue nil
        response.answers.each do |answer|
          yield answer
        end
      end
    end
  end

  # :ditto:
  def self.query(domain : String, query_records : Enumerable(RecordType | UInt16)) : Array(DNS::Packet::ResourceRecord)
    answers = Array(DNS::Packet::ResourceRecord).new(query_records.size)
    query(domain, query_records) do |answer|
      answers << answer
    end
    answers
  end

  def self.reverse_lookup(ip : Socket::IPAddress) : Array(String)
    ptr = case ip.family
          in .inet?
            # Build IPv4 PTR DNS domain, e.g. "192.0.2.1" => "1.2.0.192.in-addr.arpa"
            octets = ip.address.split('.')
            "#{octets.reverse.join(".")}.in-addr.arpa"
          in .inet6?
            address = Resource::AAAA.expand_ipv6(ip)
            reversed_nibbles = address.gsub(":", "").chars.reverse!
            "#{reversed_nibbles.join(".")}.ip6.arpa"
          in .unix?, .unspec?
            raise ArgumentError.new("IPAddress must be one of INET or INET6, not #{ip.family}")
          end

    query(ptr, [RecordType::PTR]).compact_map do |answer|
      if answer.record_type.ptr?
        answer.resource.as(Resource::PTR).domain_name
      end
    end
  end
end

require "./dns/*"

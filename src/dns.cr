# An extensible DNS implementation that doesn't block the event loop
module DNS
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  class_property timeout : Time::Span = 1.second
  class_property cache : Cache { SimpleCache.new }
  class_property default_resolver : Resolver { Resolver::UDP.new }
  class_getter resolvers : Hash(Regex, Resolver) = Hash(Regex, Resolver){
    /.+\.local$/i => Resolver::MDNS.new,
  }

  # Opcode: Specifies the kind of query in this message.
  enum OpCode : UInt8
    QUERY  = 0 # a standard query
    IQUERY = 1 # an inverse query
    STATUS = 2 # a server status request
  end

  enum RecordCode : UInt16
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

  # return the raw DNS responses without processing the answers / using cache
  def self.raw_query(domain : String, query_records : Array(RecordCode | UInt16)) : Array(DNS::Packet)
    # select a resolver for this domain (i.e. mDNS for .local domains)
    resolver = select_resolver(domain)

    # generate request ids
    query_records = query_records.map { |query| query.is_a?(RecordCode) ? query.value : query }
    queries_to_send = Hash(UInt16, UInt16).new(0_u16, query_records.size)
    query_records.each do |query|
      # find a unique id for this request
      query_id = rand(UInt16::MAX)
      loop do
        break if queries_to_send[query_id]?.nil?
        query_id = rand(UInt16::MAX)
      end
      queries_to_send[query_id] = query
    end

    answers = [] of DNS::Packet
    resolver.select_server do |dns_server|
      resolver.query(domain, dns_server, queries_to_send) do |response|
        answers << response
      end
    end
    answers
  end

  # query the DNS records of a domain and return the answers
  def self.query(domain : String, query_records : Array(RecordCode | UInt16)) : Array(DNS::Packet::ResourceRecord)
    answers = [] of DNS::Packet::ResourceRecord
    query_records = query_records.map { |query| query.is_a?(RecordCode) ? query.value : query }

    # Check cache and collect the queries we need to transmit
    queries_to_send = {} of UInt16 => UInt16
    cache_local = cache
    query_records.each do |query|
      cached_record = cache_local.lookup(domain, query)
      if cached_record
        answers << cached_record
        next
      end

      # find a unique id for this request
      query_id = rand(UInt16::MAX)
      loop do
        break if queries_to_send[query_id]?.nil?
        query_id = rand(UInt16::MAX)
      end
      queries_to_send[query_id] = query
    end

    # return if all queries are answered from cache
    return answers if queries_to_send.empty?

    # select a resolver for this domain (i.e. mDNS for .local domains)
    resolver = select_resolver(domain)

    # Track which questions have been answered so far
    questions_answered = Array(UInt16).new(queries_to_send.size)

    # query the server
    resolver.select_server do |dns_server|
      queries_to_send.reject!(questions_answered)

      resolver.query(domain, dns_server, queries_to_send) do |response|
        # raise any errors,
        # ServerError will be handled by moving to the next DNS server, assuming there is one
        # other errors indicate an issue with the request and will be propagated
        response.raise_on_error!
        answers.concat response.answers
        questions_answered << response.id
        cache.store(domain, response)
      end
    end

    answers
  end
end

require "./dns/*"

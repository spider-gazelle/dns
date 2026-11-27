require "log"
require "random/secure"

# An extensible DNS implementation that doesn't block the event loop
module DNS
  Log = ::Log.for(self)

  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  # The base (initial) per-try timeout for a DNS query.
  #
  # This is the starting point for the resolver's exponential backoff (the
  # `attempts` and per-try timeout are sourced from `DNS::Servers`, which honours
  # `resolv.conf`'s `timeout:` / `attempts:` options). Modelled on glibc's
  # `RES_TIMEOUT` (5s) but defaulting to a snappier 2s as we retransmit.
  class_property timeout : Time::Span = 2.seconds
  class_property default_resolver : Resolver { Resolver::UDP.new }
  class_getter resolvers : Hash(Regex, Resolver) = Hash(Regex, Resolver){
    /.+\.local$/i => Resolver::MDNS.new,
  }
  class_property cache : Cache { Cache::HashMap.new }
  @@cache_lock = Mutex.new

  def self.cache=(cache : Cache)
    @@cache_lock.synchronize do
      old = @@cache
      previous_def(cache)
      old.close if old && old != cache
    end
    cache
  end

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
  def self.select_resolver(domain : String, *, fallback : Resolver = default_resolver) : Resolver
    domain = domain.rchop('.')
    resolvers.each do |regex, res|
      return res if regex.matches?(domain)
    end
    fallback
  end

  # query the DNS records of a domain and return the answers
  #
  # Automatically expands domain names using the resolver's search domains and ndots settings.
  # Tries expanded candidates in order until one answers a requested record type.
  # Network results are cached under the candidate name and its resolver.
  # Set `default_resolver` to `Resolver::Validating` to require local DNSSEC
  # validation for every answer, bypassing the hosts file, cache, and routes.
  #
  # NOTE:: A or AAAA answers may include cname and other records that are not directly relevent to the query.
  # It is up to the consumer to filter for the relevant results
  # ameba:disable Metrics/CyclomaticComplexity
  def self.query(domain : String, query_records : Enumerable(RecordType | UInt16), &) : Nil
    fallback = default_resolver
    if fallback.is_a?(Resolver::Validating)
      query_validated(domain, query_records, fallback).each { |answer| yield answer }
      return
    end

    if Socket::IPAddress.valid?(domain)
      record_type = Socket::IPAddress.valid_v4?(domain) ? RecordType::A : RecordType::AAAA
      record_type_int = record_type.to_u16
      if query_records.includes?(record_type) || query_records.includes?(record_type_int)
        resource = record_type.a? ? Resource::A.new(domain) : Resource::AAAA.new(domain)
        yield DNS::Packet::ResourceRecord.new(domain, record_type_int, ClassCode::Internet.to_u16, 1.day, resource)
      end
      return
    end

    original_name = normalize_name(domain)
    query_records_set = query_records.map { |query| query.is_a?(RecordType) ? query.value : query }.to_set
    queries_to_send = {} of UInt16 => UInt16

    query_records_set.each do |record|
      if host = Hosts.lookup(original_name, record)
        yield host
        next
      end

      # find a unique id for this request
      # uses a CSPRNG over the full 16-bit space (RFC 5452) to harden against
      # off-path response spoofing
      query_id = Random::Secure.rand(UInt16)
      loop do
        break if queries_to_send[query_id]?.nil?
        query_id = Random::Secure.rand(UInt16)
      end
      queries_to_send[query_id] = record
    end

    return if queries_to_send.empty?

    resolver = select_resolver(domain, fallback: fallback)
    candidates = resolver.server_config.expand(domain).map { |name| normalize_name(name) }.uniq!
    cache_local = cache
    if candidates.size == 1
      query_candidate(candidates.first, queries_to_send, resolver, cache_local) do |answer|
        yield answer
      end
      return
    end

    requested_types = queries_to_send.values.to_set
    search_candidates(candidates, requested_types) do |candidate|
      candidate_resolver = candidate == original_name ? resolver : select_resolver(candidate, fallback: resolver)
      answers = [] of Packet::ResourceRecord
      query_candidate(candidate, queries_to_send, candidate_resolver, cache_local) { |answer| answers << answer }
      answers
    end.each { |answer| yield answer }
  end

  private def self.query_validated(
    domain : String,
    query_records : Enumerable(RecordType | UInt16),
    resolver : Resolver::Validating,
  ) : Array(Packet::ResourceRecord)
    requested_types = query_records.map(&.to_u16).to_set
    return [] of Packet::ResourceRecord if requested_types.empty?
    original_name = normalize_name(domain)
    if original_name == "localhost" || original_name.ends_with?(".localhost")
      return loopback_answers(original_name, requested_types)
    end
    if Socket::IPAddress.valid?(domain)
      raise DNSSEC::ValidationError.new(DNSSEC::Status::Indeterminate, "DNSSEC cannot authenticate an IP literal")
    end

    candidates = resolver.server_config.expand(domain).map { |name| normalize_name(name) }.uniq!
    search_candidates(candidates, requested_types) do |candidate|
      resolver.validated_answers(candidate, requested_types)
    end
  end

  # RFC 6761 section 6.3: localhost names always resolve to loopback and are
  # never sent upstream, so strict lookups do not depend on the hosts file.
  private def self.loopback_answers(name : String, requested_types : Set(UInt16)) : Array(Packet::ResourceRecord)
    requested_types.compact_map do |type|
      resource = case type
                 when Resource::A::RECORD_TYPE    then Resource::A.new("127.0.0.1")
                 when Resource::AAAA::RECORD_TYPE then Resource::AAAA.new("::1")
                 end
      Packet::ResourceRecord.new(name, type, ClassCode::Internet.value, 0.seconds, resource) if resource
    end
  end

  private def self.search_candidates(candidates : Array(String), requested_types : Set(UInt16), &) : Array(Packet::ResourceRecord)
    first_empty_answer : Array(Packet::ResourceRecord)? = nil
    first_name_error : Packet::NameError? = nil
    candidates.each do |candidate|
      answers = yield candidate
      return answers if answers.any? { |answer| requested_types.includes?(answer.type) }
      first_empty_answer ||= answers
    rescue ex : Packet::NameError
      first_name_error ||= ex
    end

    return first_empty_answer if first_empty_answer
    raise first_name_error if first_name_error
    [] of Packet::ResourceRecord
  end

  private def self.normalize_name(name : String) : String
    URI::Punycode.to_ascii(name.rchop('.').downcase)
  end

  private def self.query_candidate(
    domain : String,
    queries_to_send : Hash(UInt16, UInt16),
    resolver : Resolver,
    cache_local : Cache,
    &
  ) : Nil
    scoped_name = Cache.scoped_name(domain, resolver.cache_scope)
    outstanding = queries_to_send.reject do |_, type|
      records = cache_local.lookup_all(scoped_name, type) || cache_local.lookup_all(domain, type)
      if records
        records.each { |record| yield record }
        true
      else
        denial = cache_local.lookup_negative(scoped_name, type)
        if denial && denial.name_error?
          error = Packet::NameError.new("Hostname lookup for #{domain} failed")
          error.extended_errors = denial.extended_errors
          raise error
        end
        !denial.nil?
      end
    end
    return if outstanding.empty?

    resolver.select_server do |dns_server, timeout|
      Log.trace { "Querying #{dns_server} -- domain: #{domain.inspect}, records: #{outstanding.values}" }
      resolver.query(domain, dns_server, outstanding.dup, timeout) do |response|
        if type = outstanding[response.id]?
          begin
            cache_local.store_negative_answer(domain, type, response, scope: resolver.cache_scope)
          rescue ex
            Log.trace(exception: ex) { "could not cache negative DNS response for #{domain}" }
          end
        end
        response.raise_on_error!
        outstanding.delete(response.id)
        begin
          cache_local.store(domain, response, scope: resolver.cache_scope)
        rescue ex
          Log.trace(exception: ex) { "could not cache DNS response for #{domain}" }
        end

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

  # Query a fully qualified name and return the upstream packet, including
  # DNSSEC flags and authority records. Packet queries bypass the library's
  # hosts file, response cache, search suffixes, and local DNSSEC validation.
  # NXDOMAIN and other non-retryable DNS responses are returned as packets.
  def self.query_packet(
    domain : String,
    record : RecordType | UInt16,
    *,
    resolver : Resolver = select_resolver(domain),
    dnssec : DNSSEC::Options = DNSSEC::Options.new,
  ) : Packet
    resolver = resolver.upstream if resolver.is_a?(Resolver::Validating)
    name = normalize_name(domain)
    fetch = {Random::Secure.rand(UInt16) => record.to_u16}
    packet : Packet? = nil
    resolver.select_server do |server, timeout|
      packet = nil
      resolver.query(name, server, fetch.dup, timeout, dnssec: dnssec) do |response|
        response.raise_on_error! if response.server_error?
        if dnssec.dnssec_ok? && (response.edns.nil? || response.edns_rejected?)
          error = Packet::ServerError.new("DNS server #{server} did not provide EDNS required for DNSSEC")
          error.extended_errors = response.extended_errors
          raise error
        end
        packet = response
      end
      raise IO::Error.new("DNS server #{server} did not return a packet for #{name}") unless packet
    end
    packet || raise IO::Error.new("DNS lookup returned no packet for #{name}")
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

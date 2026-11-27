require "uri"
require "./packet"

# an interface for caching DNS entries up to TTL
module DNS::Cache
  record Negative, name_error : Bool, extended_errors : Array(DNS::Packet::EDNS::ExtendedError) do
    def name_error? : Bool
      name_error
    end
  end

  def lookup_negative(domain : String, query : UInt16) : Negative?
    nil
  end

  # A nil type represents NXDOMAIN for the entire name.
  def store_negative(domain : String, query : UInt16?, ttl : Time::Span, *, extended_errors = [] of DNS::Packet::EDNS::ExtendedError) : Nil
  end

  # check for a cached record
  abstract def lookup(domain : String, query : UInt16) : DNS::Packet::ResourceRecord?

  # Fetch a complete cached RRset. Legacy caches can still return one record.
  def lookup_all(domain : String, query : UInt16) : Array(DNS::Packet::ResourceRecord)?
    lookup(domain, query).try { |record| [record] }
  end

  # store a result in the cache
  abstract def store(domain : String, result : DNS::Packet::ResourceRecord) : Nil

  # cleanup any expired entries
  abstract def cleanup : Nil

  # remove all entries
  abstract def clear : Nil

  # called when replaced with a different cache, stops cleanup fiber
  abstract def close : Nil

  # Stores the records of the same name and type from a single section.
  def store_rrset(domain : String, records : Array(DNS::Packet::ResourceRecord), *, additional : Bool = false) : Nil
    return if records.empty?
    return if additional && lookup(domain, records.first.type)
    records.each { |record| store(domain, record) }
  end

  def self.scoped_name(domain : String, scope : UInt64?) : String
    scope ? "#{scope}\0#{domain}" : domain
  end

  def store_negative_answer(domain : String, query : UInt16, response : DNS::Packet, *, scope : UInt64? = nil) : Nil
    code = response.effective_response_code
    return unless code.in?({0, 3})
    return if response.truncation? || response.answers.any? { |record| record.type == query }

    # An alias in a negative answer still exists. The denial applies to its target.
    name = alias_chain_ttls(domain, response.answers).keys.last? || normalize_name(domain)
    zone = response.authorities.select do |record|
      next false unless record.class_code == ClassCode::Internet.value && record.resource.is_a?(Resource::SOA)
      owner = normalize_name(record.name)
      owner.empty? || name == owner || name.ends_with?(".#{owner}")
    end.max_by?(&.name.bytesize)
    return unless zone

    soa = zone.resource.as(Resource::SOA)
    ttl = {zone.ttl, soa.minimum_ttl}.min
    store_negative(DNS::Cache.scoped_name(name, scope), code == 3 ? nil : query, ttl, extended_errors: response.extended_errors)
  end

  def store(domain : String, response : DNS::Packet, *, scope : UInt64? = nil)
    answers = response.answers.select { |record| cacheable_record?(record) }
    # Cache answers for the question's name, including terminal alias records.
    cache_name = DNS::Cache.scoped_name(domain, scope)
    alias_ttls = alias_chain_ttls(domain, answers)
    answers.group_by(&.type).each_value do |rrset|
      rrset.map! do |record|
        if ttl = alias_ttls[normalize_name(record.name)]?
          record.ttl = {record.ttl, ttl}.min
        end
        record
      end unless alias_ttls.empty?
      store_rrset(cache_name, rrset)
    end

    additionals = response.additionals
    return if additionals.empty?

    referenced = referenced_names(domain, answers)
    rrsets = {} of {String, UInt16} => Array(DNS::Packet::ResourceRecord)
    additionals.each do |additional|
      next unless cacheable_record?(additional)
      name = normalize_name(additional.name)
      next unless referenced.includes?(name)
      (rrsets[{name, additional.type}] ||= [] of DNS::Packet::ResourceRecord) << additional
    end
    rrsets.each do |(name, _type), rrset|
      store_rrset(DNS::Cache.scoped_name(name, scope), rrset, additional: true)
    end
  end

  # Cache entries for an alias depend on every CNAME between it and the record.
  private def alias_chain_ttls(domain : String, answers : Array(DNS::Packet::ResourceRecord)) : Hash(String, Time::Span)
    aliases = {} of String => {String, Time::Span}
    answers.each do |record|
      if cname = record.resource.as?(Resource::CNAME)
        aliases[normalize_name(record.name)] = {normalize_name(cname.target), record.ttl}
      end
    end

    ttls = {} of String => Time::Span
    origin = name = normalize_name(domain)
    minimum : Time::Span? = nil
    while entry = aliases[name]?
      target, ttl = entry
      break if target == origin || ttls.has_key?(target)
      minimum = {minimum || ttl, ttl}.min
      ttls[target] = minimum
      name = target
    end
    ttls
  end

  private def cacheable_record?(record : DNS::Packet::ResourceRecord) : Bool
    record.type != DNS::RecordType::OPT.value && record.class_code == DNS::ClassCode::Internet.value
  end

  # The set of names the answer section vouches for: the queried name, the owner
  # name of each answer, and any hostname an answer points at (CNAME/DNAME target,
  # NS nsdname, MX exchange, SRV target).
  private def referenced_names(domain : String, answers : Array(DNS::Packet::ResourceRecord)) : Set(String)
    names = Set(String){normalize_name(domain)}
    answers.each do |answer|
      names << normalize_name(answer.name)
      if target = referenced_target(answer)
        names << normalize_name(target)
      end
    end
    names
  end

  # The hostname an answer record points at, if any. Switches on the raw type
  # value so an unknown record type can never raise.
  private def referenced_target(record : DNS::Packet::ResourceRecord) : String?
    case record.type
    when Resource::CNAME::RECORD_TYPE then record.resource.as?(Resource::CNAME).try(&.target)
    when Resource::DNAME::RECORD_TYPE then record.resource.as?(Resource::DNAME).try(&.target)
    when Resource::NS::RECORD_TYPE    then record.resource.as?(Resource::NS).try(&.name_server)
    when Resource::MX::RECORD_TYPE    then record.resource.as?(Resource::MX).try(&.exchange)
    when Resource::SRV::RECORD_TYPE   then record.resource.as?(Resource::SRV).try(&.target)
    end
  end

  private def normalize_name(name : String) : String
    URI::Punycode.to_ascii(name.rchop('.').downcase)
  end
end

require "./cache/*"

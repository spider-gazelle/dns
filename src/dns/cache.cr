require "uri"
require "./packet"

# an interface for caching DNS entries up to TTL
module DNS::Cache
  # check for a cached record
  abstract def lookup(domain : String, query : UInt16) : DNS::Packet::ResourceRecord?

  # store a result in the cache
  abstract def store(domain : String, result : DNS::Packet::ResourceRecord) : Nil

  # cleanup any expired entries
  abstract def cleanup : Nil

  # remove all entries
  abstract def clear : Nil

  # called when replaced with a different cache, stops cleanup fiber
  abstract def close : Nil

  def store(domain : String, response : DNS::Packet)
    # answers resolve the queried name (including any CNAME chain), so they are
    # cached against the queried name
    response.answers.each { |answer| store(domain, answer) }

    # The "Additional" section carries records for OTHER names - e.g. the A/AAAA
    # glue for an MX/NS/SRV/CNAME target referenced in the answers. Each must be
    # cached under its OWN name (not the queried name), and only when that name
    # is vouched for by the answer section (a bailiwick check) so a server cannot
    # seed the cache with records unrelated to the request.
    additionals = response.additionals
    return if additionals.empty?

    in_bailiwick = referenced_names(domain, response.answers)
    additionals.each do |additional|
      name = normalize_name(additional.name)
      store(name, additional) if in_bailiwick.includes?(name)
    end
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
    URI::Punycode.to_ascii(name.downcase)
  end
end

require "./cache/*"

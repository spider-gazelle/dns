require "./resource_record"

# an interface for caching DNS entries up to TTL
module DNS::Cache
  # check for a cached record
  abstract def lookup(domain : String, query : Query) : DNS::ResourceRecord?

  # store a result in the cache
  abstract def store(domain : String, result : DNS::ResourceRecord)

  # cleanup any expired entries
  abstract def cleanup : Nil

  def store(domain : String, response : DNS::Response)
    response.answers.each { |answer| store(domain, answer) }

    # If a DNS query asks for an MX (Mail Exchange) record,
    # the response might include the mail server's hostname in the Answer section.
    # The "Additional" section can include the corresponding A or AAAA records for the mail server
    response.additionals.each { |answer| store(domain, answer) }
  end
end

require "./cache/*"

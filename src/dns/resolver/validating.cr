# Requires local DNSSEC authentication for DNS.query when installed as the
# default resolver. Uses the configured upstream for all validation lookups.
class DNS::Resolver::Validating < DNS::Resolver
  getter upstream : Resolver

  def initialize(upstream : Resolver, *, trust_anchors : Array(DNSSEC::TrustAnchor) = DNSSEC::Validator.root_anchors)
    @upstream = upstream.is_a?(Validating) ? upstream.upstream : upstream
    @servers = @upstream.servers
    @server_config = @upstream.server_config
    @validator = DNSSEC::Validator.new(@upstream, trust_anchors: trust_anchors)
  end

  # :nodoc:
  def validated_answers(domain : String, types : Set(UInt16)) : Array(Packet::ResourceRecord)
    now = Time.utc
    types.flat_map do |type|
      result = require_secure(domain, type, now)
      if result.response_code == 3
        raise Packet::NameError.new("Hostname lookup for #{domain} failed")
      end
      result.answers
    end
  end

  # Returns a packet containing only the locally authenticated results.
  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), timeout : Time::Span, & : Packet ->)
    now = Time.utc
    responses = fetch.map do |id, type|
      result = require_secure(domain, type, now)
      question = Packet::Question.new(domain, type, ClassCode::Internet.value)
      Packet.new(id: id, response: true, questions: [question], answers: result.answers,
        response_code: result.response_code == 3 ? 3_u8 : 0_u8, authenticated_data: true)
    end
    responses.each { |response| yield response }
  end

  private def require_secure(domain : String, type : UInt16, now : Time) : DNSSEC::Result
    result = @validator.query(domain, type, now: now)
    return result if result.secure?
    raise DNSSEC::ValidationError.new(result.status, "DNSSEC validation for #{domain} type #{type} returned #{result.status}. #{result.reason}")
  end
end

require "http/client"

class DNS::Resolver::HTTPS < DNS::Resolver
  DNS_MESSAGE = "application/dns-message"

  # Provide your own server list (list of DoH server URLs)
  def initialize(@servers : Array(String), @tls_context : OpenSSL::SSL::Context::Client? = nil)
  end

  # Optionally, allow custom TLS context
  property tls_context : OpenSSL::SSL::Context::Client?

  # Perform the DNS query, fetching using request_id => record_type
  def query(
    domain : String,
    dns_server : String,
    fetch : Hash(UInt16, UInt16),
    timeout : Time::Span = ::DNS.timeout,
    & : DNS::Packet ->
  )
    uri = URI.parse(dns_server)
    hostname = uri.hostname || raise ArgumentError.new("DNS-over-HTTPS endpoint requires a hostname")
    client = HTTP::Client.new(uri, tls: @tls_context)
    client.dns_timeout = timeout
    client.connect_timeout = timeout
    client.write_timeout = timeout
    client.read_timeout = timeout

    begin
      fetch.each do |id, record|
        # Build the DNS query bytes
        query_bytes = DNS::Packet::Question.build_query(domain, record, 0_u16, edns: query_edns)

        # Build the HTTP request
        request = HTTP::Request.new("POST", uri.request_target)
        request.headers["Content-Type"] = DNS_MESSAGE
        request.headers["Accept"] = DNS_MESSAGE
        request.headers["Content-Length"] = query_bytes.size.to_s
        request.body = IO::Memory.new(query_bytes)

        dns_response = Resolver.with_system_resolution(hostname) do
          request_packet(client, request, domain, record)
        end
        dns_response.id = id
        yield dns_response
      end
    rescue ex : OpenSSL::Error
      raise IO::Error.new("DNS-over-HTTPS query to #{dns_server} failed", cause: ex)
    ensure
      client.close
    end
  end

  private def request_packet(client : HTTP::Client, request : HTTP::Request, domain : String, record : UInt16) : DNS::Packet
    client.exec(request) do |response|
      raise DNS::Packet::ServerError.new("DNS query failed with HTTP status #{response.status_code}") unless response.success?
      unless response.headers["Content-Type"]?.try(&.split(';', 2).first.strip.downcase) == DNS_MESSAGE
        raise DNS::Packet::ServerError.new("unexpected DNS-over-HTTPS response content type")
      end
      body = response.body_io || raise DNS::Packet::ServerError.new("missing DNS-over-HTTPS response body")
      packet = DNS::Packet.from_io(body)
      unless packet.matches_question?(domain, record, 0_u16, allow_missing_question: !packet.success?)
        raise DNS::Packet::ServerError.new("DNS-over-HTTPS response does not match the question")
      end
      packet
    end
  end
end

require "http/client"

class DNS::Resolver::HTTPS < DNS::Resolver
  # Provide your own server list (list of DoH server URLs)
  def initialize(@servers : Array(String), @tls_context : OpenSSL::SSL::Context::Client? = nil)
  end

  # Optionally, allow custom TLS context
  property tls_context : OpenSSL::SSL::Context::Client?

  # Perform the DNS query, fetching using request_id => record_type
  def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)
    uri = URI.parse(dns_server)
    client = HTTP::Client.new(uri, tls: @tls_context)

    begin
      fetch.each do |id, record|
        # Build the DNS query bytes
        query_bytes = DNS::Packet::Question.build_query(domain, record, id)

        # Build the HTTP request
        request = HTTP::Request.new("POST", uri.request_target)
        request.headers["Content-Type"] = "application/dns-message"
        request.headers["Content-Length"] = query_bytes.size.to_s
        request.body = IO::Memory.new(query_bytes)

        # Send the request
        response = client.exec(request)

        # Check the response
        raise DNS::Packet::ServerError.new("DNS query failed with HTTP status #{response.status_code}") unless response.success?
        dns_response = DNS::Packet.from_slice(response.body.to_slice)
        yield dns_response
      end
    ensure
      client.close
    end
  end
end

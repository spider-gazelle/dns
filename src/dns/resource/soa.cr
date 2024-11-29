module DNS
  # SOA record parsing
  struct Resource::SOA
    include Resource

    RECORD_TYPE = 6_u16

    getter primary_ns : String      # Primary name server for the domain
    getter admin_email : String     # Email of the administrator (encoded as a domain)
    getter serial : UInt32          # Serial number for the zone
    getter refresh : Time::Span     # Time interval (in seconds) before the zone should be refreshed
    getter retry : Time::Span       # Time interval before retrying a failed refresh attempt
    getter expire : Time::Span      # Time after which the zone is no longer authoritative
    getter minimum_ttl : Time::Span # Minimum TTL value for the zone

    def initialize(resource_data : Bytes, message : Bytes)
      io = IO::Memory.new(resource_data)

      # Read the primary name server (NS) as a domain name
      @primary_ns = Resource.read_labels(io, message)

      # Read the administrator's email as a domain name (with the first "." replaced by "@")
      email = Resource.read_labels(io, message)
      @admin_email = if email.includes?("\\.")
                       parts = email.split("\\.")
                       parts[-1] = parts[-1].sub('.', '@')
                       parts.join('.')
                     else
                       email.sub('.', '@')
                     end

      # Read the 32-bit values for serial, refresh, retry, expire, and minimum TTL
      @serial = io.read_bytes(UInt32, IO::ByteFormat::BigEndian)
      @refresh = io.read_bytes(UInt32, IO::ByteFormat::BigEndian).seconds
      @retry = io.read_bytes(UInt32, IO::ByteFormat::BigEndian).seconds
      @expire = io.read_bytes(UInt32, IO::ByteFormat::BigEndian).seconds
      @minimum_ttl = io.read_bytes(UInt32, IO::ByteFormat::BigEndian).seconds
    end
  end
end

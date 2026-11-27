# DNSSEC signaling for a stub resolver using an upstream recursive server.
module DNS::DNSSEC
  struct Options
    # Request DNSSEC records with the EDNS DNSSEC OK (DO) bit.
    getter? dnssec_ok : Bool

    # Ask the upstream to report authentication with the AD header bit.
    getter? request_ad : Bool

    # Ask the upstream to return data even when validation fails (CD).
    getter? checking_disabled : Bool

    def initialize(
      *,
      @dnssec_ok : Bool = false,
      @request_ad : Bool = false,
      @checking_disabled : Bool = false,
    )
    end

    def requested? : Bool
      dnssec_ok? || request_ad? || checking_disabled?
    end
  end

  class UnsupportedResolver < DNS::Packet::Error
  end
end

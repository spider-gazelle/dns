module DNS
  # Child DNSKEY published for the parent zone (RFC 7344).
  struct Resource::CDNSKEY
    include Resource

    RECORD_TYPE = 60_u16

    def initialize(resource_data : Bytes, message : Bytes)
      @dnskey = DNSKEY.new(resource_data, message)
    end

    delegate flags, protocol, algorithm, public_key, key_tag, zone_key?, revoked?, secure_entry_point?, to: @dnskey

    # Identifies the exact RFC 8078 deletion record. The parent must validate
    # the entire RRset and apply its acceptance policy before acting on it.
    def delete_signal? : Bool
      flags.zero? && protocol == 3 && algorithm.zero? && public_key.size == 1 && public_key[0].zero?
    end
  end
end

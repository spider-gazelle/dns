module DNS
  # Child Delegation Signer data published for the parent zone (RFC 7344).
  struct Resource::CDS
    include Resource

    RECORD_TYPE = 59_u16

    def initialize(resource_data : Bytes, message : Bytes)
      @ds = DS.new(resource_data, message)
    end

    delegate key_tag, algorithm, digest_type, digest, to: @ds

    # Identifies the exact RFC 8078 deletion record. The parent must validate
    # the entire RRset and apply its acceptance policy before acting on it.
    def delete_signal? : Bool
      key_tag.zero? && algorithm.zero? && digest_type.zero? && digest.size == 1 && digest[0].zero?
    end
  end
end

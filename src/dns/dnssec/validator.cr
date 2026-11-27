module DNS::DNSSEC
  enum Status
    Secure
    Insecure
    Bogus
    Indeterminate
  end

  class ValidationError < Exception
    getter status : Status

    def initialize(@status : Status, message : String)
      super(message)
    end
  end

  # A configured DS trust anchor. A closer configured anchor takes precedence.
  record TrustAnchor, zone : String, key_tag : UInt16, algorithm : UInt8, digest_type : UInt8, digest : Bytes

  record Result, status : Status, answers : Array(Packet::ResourceRecord), response_code : UInt16?, reason : String? do
    def secure? : Bool
      status.secure?
    end
  end

  # A validating stub. Each lookup uses a fresh validation context and returns
  # only answer records that were authenticated locally.
  class Validator
    # Current IANA root KSK digests, including the published rollover key.
    # https://www.iana.org/dnssec/files
    def self.root_anchors : Array(TrustAnchor)
      [
        TrustAnchor.new(".", 20326_u16, 8_u8, 2_u8, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D".hexbytes),
        TrustAnchor.new(".", 38696_u16, 8_u8, 2_u8, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16".hexbytes),
      ]
    end

    def initialize(@resolver : Resolver = DNS.default_resolver, *, trust_anchors : Array(TrustAnchor) = Validator.root_anchors)
      raise ArgumentError.new("a DNSSEC validator needs a trust anchor") if trust_anchors.empty?
      @anchors = {} of Wire::Name => Array(Crypto::DS)
      trust_anchors.each do |anchor|
        zone = Wire::Name.from_text(anchor.zone)
        entry = Crypto::DS.new(anchor.key_tag, anchor.algorithm, anchor.digest_type, anchor.digest.dup)
        raise ArgumentError.new("unsupported DNSSEC trust anchor for #{zone}") unless entry.supported?
        (@anchors[zone] ||= [] of Crypto::DS) << entry
      end
    end

    def query(domain : String, type : RecordType | UInt16, *, now : Time = Time.utc) : Result
      name = Wire::Name.from_text(domain)
      Validation.new(@resolver, @anchors, now.to_unix.to_u32!).query(name, type.to_u16)
    end
  end

  # :nodoc:
  class Validation
    alias Name = Wire::Name
    alias RR = Wire::RR
    alias Message = Wire::Message
    alias Signature = Crypto::Signature
    alias Key = Crypto::Key

    private OPTS           = Options.new(dnssec_ok: true, checking_disabled: true)
    private MAX_QUERIES    =  64
    private MAX_SIGNATURES = 256
    private MAX_ALIASES    =  16
    private MAX_PROOFS     =  64

    @messages = {} of {Name, UInt16} => Message
    @keys = {} of Name => Array(Key)
    @failed_keys = {} of Name => ValidationError
    @remaining_queries = MAX_QUERIES
    @remaining_signatures = MAX_SIGNATURES

    def initialize(@resolver : Resolver, @anchors : Hash(Name, Array(Crypto::DS)), @now : UInt32)
    end

    def query(name : Name, type : UInt16) : Result
      check_query_type(type)
      message = fetch(name, type)
      current = name
      seen = Set(Name).new
      result = [] of Packet::ResourceRecord
      loop do
        unless seen.size <= MAX_ALIASES && seen.add?(current)
          raise ValidationError.new(Status::Bogus, "DNS alias loop or excessive alias chain")
        end

        records = message.answer(current, type)
        unless records.empty?
          raise ValidationError.new(Status::Bogus, "NXDOMAIN response contains a positive answer") unless message.code.zero?
          if type == RecordType::CNAME.value
            follow_alias(result, records, message)
          else
            add_authenticated(result, records, message)
          end
          return Result.new(Status::Secure, result, message.code, nil)
        end

        chain = message.answer(current, RecordType::CNAME.value)
        return negative_result(result, message, current, type) if chain.empty?

        current = follow_alias(result, chain, message)
        if message.code.zero? && needs_alias_fetch?(message, current, type)
          message = fetch(current, type)
        end
      end
    rescue ex : ValidationError
      Result.new(ex.status, [] of Packet::ResourceRecord, message.try(&.code), ex.message)
    rescue ex : IO::Error | Packet::Error | OpenSSL::Error
      Result.new(Status::Indeterminate, [] of Packet::ResourceRecord, message.try(&.code), ex.message)
    rescue IndexError | OverflowError
      Result.new(Status::Bogus, [] of Packet::ResourceRecord, message.try(&.code), "malformed DNSSEC wire data")
    end

    private def check_query_type(type : UInt16) : Nil
      if type.in?({0_u16, RecordType::OPT.value, RecordType::RRSIG.value}) || type.in?(249_u16..255_u16)
        raise ValidationError.new(Status::Indeterminate, "DNSSEC validation requires a concrete, signable RR type")
      end
    end

    private def negative_result(answers : Array(Packet::ResourceRecord), message : Message, name : Name, type : UInt16) : Result
      status = prove_negative(message, name, type)
      return Result.new(status, answers, message.code, nil) if status.secure?
      raise ValidationError.new(status, "denial is within an unsigned DNSSEC delegation")
    end

    private def follow_alias(answers : Array(Packet::ResourceRecord), chain : Array(RR), message : Message) : Name
      target = alias_target(chain)
      name = chain.first.name
      if signatures(chain, message.answers).empty? && (dname = enclosing_dname(name, message))
        validate_synthesis(answers, chain, target, dname, message)
      else
        add_authenticated(answers, chain, message)
      end
      target
    end

    private def alias_target(records : Array(RR)) : Name
      targets = records.map do |record|
        io = IO::Memory.new(record.data)
        target = Name.read(io, record.data, compression: false)
        raise ValidationError.new(Status::Bogus, "invalid DNS alias record") unless io.pos == io.size
        target
      end.uniq!
      raise ValidationError.new(Status::Bogus, "DNS alias RRset has multiple targets") unless targets.size == 1
      targets.first
    end

    private def enclosing_dname(name : Name, message : Message) : Name?
      message.answers.select do |record|
        record.type == RecordType::DNAME.value && record.name.size < name.size && name.within?(record.name)
      end.max_by?(&.name.size).try(&.name)
    end

    private def validate_synthesis(answers : Array(Packet::ResourceRecord), chain : Array(RR), target : Name, owner : Name, message : Message) : Nil
      records = message.answer(owner, RecordType::DNAME.value)
      ttl = authenticate(records, message.answers, message)
      prefix = chain.first.name.labels.first(chain.first.name.size - owner.size)
      replacement = Name.new(prefix + alias_target(records).labels)
      if target != replacement || replacement.labels.sum { |label| label.bytesize + 1 } >= 255
        raise ValidationError.new(Status::Bogus, "CNAME is inconsistent with the authenticated DNAME")
      end
      (records + chain).each { |record| answers << record.public_record(ttl) }
    end

    private def needs_alias_fetch?(message : Message, name : Name, type : UInt16) : Bool
      message.answer(name, type).empty? &&
        message.answer(name, RecordType::CNAME.value).empty? &&
        message.authorities.none? { |record| record.type == RecordType::SOA.value && name.within?(record.name) }
    end

    private def fetch(name : Name, type : UInt16) : Message
      @messages[{name, type}] ||= begin
        raise ValidationError.new(Status::Indeterminate, "DNSSEC query budget exceeded") if @remaining_queries.zero?
        @remaining_queries -= 1
        packet = DNS.query_packet(name.query_text, type, resolver: @resolver, dnssec: OPTS)
        message = Message.new(packet)
        unless message.question == Wire::Question.new(name, type, Wire::IN)
          raise ValidationError.new(Status::Bogus, "DNSSEC reply does not echo the original question")
        end
        unless message.code.in?({0, 3})
          raise ValidationError.new(Status::Indeterminate, "upstream returned DNS response code #{message.code}")
        end
        message
      end
    end

    private def anchor_for(name : Name) : Name
      @anchors.keys.select { |zone| name.within?(zone) }.max_by?(&.size) ||
        raise ValidationError.new(Status::Indeterminate, "no configured trust anchor covers #{name}")
    end

    private def keys_for(zone : Name) : Array(Key)
      if failure = @failed_keys[zone]?
        raise failure
      end
      @keys[zone] ||= load_keys(zone)
    rescue ex : ValidationError
      @failed_keys[zone] = ex
      raise ex
    end

    private def load_keys(zone : Name) : Array(Key)
      anchor = anchor_for(zone)
      ds = zone == anchor ? @anchors[anchor] : delegated_ds(zone)
      message = fetch(zone, RecordType::DNSKEY.value)
      records = message.answer(zone, RecordType::DNSKEY.value)
      raise ValidationError.new(Status::Bogus, "missing DNSKEY RRset for #{zone}") if records.empty? || message.code != 0
      keys = records.map { |record| Key.new(record.data) }.select(&.usable?)
      trusted = keys.select { |key| ds.any?(&.matches?(zone, key)) }
      if trusted.empty? || authenticated_dnskeys(records, message, zone, trusted).nil?
        raise ValidationError.new(Status::Bogus, "DNSKEY RRset for #{zone} does not validate against its DS")
      end
      keys
    end

    private def delegated_ds(zone : Name) : Array(Crypto::DS)
      message = fetch(zone, RecordType::DS.value)
      records = message.answer(zone, RecordType::DS.value)
      if records.empty?
        if prove_negative(message, zone, RecordType::DS.value, delegation: true).insecure?
          raise ValidationError.new(Status::Insecure, "authenticated unsigned delegation at #{zone}")
        end
        raise ValidationError.new(Status::Bogus, "#{zone} is not a secure delegation")
      end

      unless message.code.zero?
        raise ValidationError.new(Status::Bogus, "negative response contains DS records for #{zone}")
      end
      authenticate(records, message.answers, message, parent_only: true)
      ds = records.map { |record| Crypto::DS.parse(record.data) }
      return ds if ds.any?(&.supported?)
      raise ValidationError.new(Status::Indeterminate, "no supported DS digest and signature algorithm for #{zone}")
    end

    private def add_authenticated(result : Array(Packet::ResourceRecord), records : Array(RR), message : Message) : Nil
      parent_only = records.first.type == RecordType::DS.value && records.first.name.size > 0
      ttl = authenticate(records, message.answers, message, parent_only: parent_only)
      records.each { |record| result << record.public_record(ttl) }
    rescue ex : ValidationError
      if ex.status.bogus? && unsigned_ancestor?(records.first.name)
        raise ValidationError.new(Status::Insecure, "answer is below an authenticated unsigned delegation")
      end
      raise ex
    end

    private def signatures(records : Array(RR), section : Array(RR)) : Array(Signature)
      first = records.first
      section.compact_map do |record|
        next unless record.type == RecordType::RRSIG.value && record.name == first.name
        next unless record.data.size >= 2 && Wire::FORMAT.decode(UInt16, record.data[0, 2]) == first.type
        Signature.new(record)
      rescue IO::Error
        nil
      end
    end

    private def authenticated_dnskeys(records : Array(RR), message : Message, zone : Name, trusted : Array(Key)) : UInt32?
      signatures(records, message.answers).each do |signature|
        next unless signature.signer == zone && signature.labels == zone.size
        ttl = verify(records, signature, trusted, zone)
        return ttl if ttl
      end
      nil
    end

    private def authenticate(records : Array(RR), section : Array(RR), message : Message, *, parent_only : Bool = false) : UInt32
      name = records.first.name
      error : ValidationError? = nil
      signatures(records, section).each do |signature|
        next unless authorized_signer?(name, signature.signer, parent_only)
        next if parent_only && signature.labels != name.size
        begin
          return authenticate_signature(records, signature, message)
        rescue ex : ValidationError
          error ||= ex
        end
      end
      raise error if error
      raise ValidationError.new(Status::Bogus, "missing DNSSEC signature for #{name} type #{records.first.type}")
    end

    private def authenticate_signature(records : Array(RR), signature : Signature, message : Message) : UInt32
      name = records.first.name
      unless Crypto.supported?(signature.algorithm)
        raise ValidationError.new(Status::Indeterminate, "unsupported DNSSEC signature algorithm #{signature.algorithm}")
      end
      signed_owner = signed_owner_for(name, signature)
      if !signed_owner || !(ttl = verify(records, signature, keys_for(signature.signer), signed_owner))
        raise ValidationError.new(Status::Bogus, "DNSSEC signature failed for #{name}")
      end
      return ttl if signed_owner == name

      proofs(message, name, only: signature.signer).each do |proof|
        status = proof.wildcard(name, signed_owner.suffix(signature.labels.to_i))
        return ttl if status == Status::Secure
        if status == Status::Insecure
          raise ValidationError.new(Status::Insecure, "wildcard denial proof crosses an opt-out interval")
        end
      end
      raise ValidationError.new(Status::Bogus, "missing DNSSEC proof for wildcard expansion at #{name}")
    end

    private def signed_owner_for(name : Name, signature : Signature) : Name?
      return if signature.labels > name.size
      owner = signature.labels == name.size ? name : name.suffix(signature.labels.to_i).wildcard
      owner if owner.within?(signature.signer)
    end

    private def authorized_signer?(name : Name, signer : Name, parent_only : Bool) : Bool
      name.within?(signer) && (!parent_only || signer.size < name.size) &&
        signer.within?(anchor_for(name))
    end

    private def verify(records : Array(RR), signature : Signature, keys : Array(Key), owner : Name) : UInt32?
      ttl = signature.ttl_at(@now)
      return unless ttl && Crypto.supported?(signature.algorithm)
      matching = keys.select { |key| key.algorithm == signature.algorithm && key.tag == signature.key_tag }
      return if matching.empty?

      data = signature.signed_data(records, owner)
      matching.each do |key|
        raise ValidationError.new(Status::Indeterminate, "DNSSEC signature budget exceeded") if @remaining_signatures.zero?
        @remaining_signatures -= 1
        return {ttl, records.min_of(&.ttl)}.min if Crypto.verify(key, signature.bytes, data)
      end
      nil
    end

    private def proofs(message : Message, name : Name, *, parent_only : Bool = false, only : Name? = nil) : Array(Denial::Proof)
      authenticated = {} of Name => Array(RR)
      error : ValidationError? = nil
      denial_records = message.authorities.select { |record| record.type.in?({RecordType::NSEC.value, RecordType::NSEC3.value}) }
      if denial_records.size > MAX_PROOFS
        raise ValidationError.new(Status::Indeterminate, "DNSSEC denial proof budget exceeded")
      end
      denial_records.group_by { |record| {record.name, record.type} }.each_value do |rrset|
        signatures(rrset, message.authorities).each do |signature|
          next unless proof_signer?(rrset.first.name, name, signature, parent_only, only)
          unless Crypto.supported?(signature.algorithm)
            error ||= ValidationError.new(Status::Indeterminate, "unsupported DNSSEC denial signature algorithm #{signature.algorithm}")
            next
          end
          begin
            if verify(rrset, signature, keys_for(signature.signer), rrset.first.name)
              (authenticated[signature.signer] ||= [] of RR).concat(rrset)
              break
            end
          rescue ex : ValidationError
            error ||= ex
          end
        end
      end
      raise error if authenticated.empty? && error
      authenticated.map { |signer, records| Denial::Proof.new(signer, records) }
    end

    private def proof_signer?(owner : Name, query : Name, signature : Signature, parent_only : Bool, only : Name?) : Bool
      signer = signature.signer
      signed_owner_for(owner, signature) == owner &&
        (!only || only == signer) && authorized_signer?(query, signer, parent_only)
    end

    private def prove_negative(message : Message, name : Name, type : UInt16, *, delegation : Bool = false) : Status
      parent_only = type == RecordType::DS.value && name.size > 0
      proofs(message, name, parent_only: parent_only).each do |proof|
        status = proof.negative(name, type, message.code, delegation: delegation)
        return status if status
      end
      if !delegation && unsigned_ancestor?(name)
        return Status::Insecure
      end
      raise ValidationError.new(Status::Bogus, "missing authenticated DNSSEC denial for #{name}")
    end

    private def unsigned_ancestor?(name : Name) : Bool
      anchor = anchor_for(name)
      name.size.downto(anchor.size + 1) do |length|
        zone = name.suffix(length)
        begin
          message = fetch(zone, RecordType::DS.value)
          next unless message.code.zero? && message.answer(zone, RecordType::DS.value).empty?
          proofs(message, zone, parent_only: true).each do |proof|
            status = proof.negative(zone, RecordType::DS.value, message.code, delegation: true)
            return true if status == Status::Insecure
          end
        rescue ex : ValidationError
          return true if ex.status.insecure?
          raise ex if ex.status.indeterminate?
        end
      end
      false
    end
  end
end

require "digest/sha256"
require "openssl/digest"
require "openssl/lib_crypto"

lib LibCrypto
  type DNSSECKey = Void*
  fun dnssec_decode_key = d2i_PUBKEY(key : DNSSECKey*, input : UInt8**, length : Long) : DNSSECKey
  fun dnssec_free_key = EVP_PKEY_free(key : DNSSECKey)
  fun dnssec_verify_init = EVP_DigestVerifyInit(context : EVP_MD_CTX, key_context : Void**, digest : EVP_MD, engine : Void*, key : DNSSECKey) : Int
  fun dnssec_verify = EVP_DigestVerify(context : EVP_MD_CTX, sig : UInt8*, sig_size : SizeT, data : UInt8*, data_size : SizeT) : Int
  fun dnssec_clear_errors = ERR_clear_error
end

module DNS::DNSSEC
  # :nodoc:
  module Crypto
    extend self

    record Key, data : Bytes do
      def algorithm : UInt8
        data[3]
      end

      def material : Bytes
        data[4..]
      end

      def usable? : Bool
        data.size > 4 && data[2] == 3 && data[0].bits_set?(1_u8) && !data[1].bits_set?(0x80_u8)
      end

      def tag : UInt16
        checksum = 0_u32
        data.each_with_index do |byte, index|
          checksum += index.even? ? byte.to_u32 << 8 : byte
        end
        ((checksum + (checksum >> 16)) & 0xffff).to_u16
      end
    end

    record DS, key_tag : UInt16, algorithm : UInt8, digest_type : UInt8, digest : Bytes do
      def self.parse(data : Bytes) : self
        raise IO::Error.new("short DS record") if data.size < 5
        new(Wire::FORMAT.decode(UInt16, data[0, 2]), data[2], data[3], data[4..])
      end

      def supported? : Bool
        digest_type.in?({2_u8, 4_u8}) && Crypto.supported?(algorithm)
      end

      def matches?(zone : Wire::Name, key : Key) : Bool
        return false unless supported? && key.usable? && algorithm == key.algorithm && key_tag == key.tag
        input = IO::Memory.new
        zone.wire(input)
        input.write(key.data)
        expected = digest_type == 2 ? Digest::SHA256.digest(input.to_slice) : OpenSSL::Digest.new("SHA384").update(input.to_slice).final
        digest == expected
      end
    end

    struct Signature
      getter type : UInt16
      getter algorithm : UInt8
      getter labels : UInt8
      getter original_ttl : UInt32
      getter expires : UInt32
      getter inception : UInt32
      getter key_tag : UInt16
      getter signer : Wire::Name
      getter prefix : Bytes
      getter bytes : Bytes
      getter ttl : UInt32

      def initialize(record : Wire::RR)
        io = IO::Memory.new(record.data)
        @type = io.read_bytes(UInt16, Wire::FORMAT)
        @algorithm = io.read_bytes(UInt8, Wire::FORMAT)
        @labels = io.read_bytes(UInt8, Wire::FORMAT)
        @original_ttl = io.read_bytes(UInt32, Wire::FORMAT)
        @expires = io.read_bytes(UInt32, Wire::FORMAT)
        @inception = io.read_bytes(UInt32, Wire::FORMAT)
        @key_tag = io.read_bytes(UInt16, Wire::FORMAT)
        @signer = Wire::Name.read(io, record.data, compression: false)
        @prefix = record.data[0, io.pos]
        @bytes = record.data[io.pos..]
        @ttl = record.ttl
        raise IO::Error.new("empty RRSIG signature") if bytes.empty?
      end

      def ttl_at(now : UInt32) : UInt32?
        age = now &- inception
        remaining = expires &- now
        return unless age < 0x80000000_u32 && remaining < 0x80000000_u32 && (expires &- inception) < 0x80000000_u32
        {ttl, original_ttl, remaining}.min
      end

      def signed_data(records : Array(Wire::RR), owner : Wire::Name) : Bytes
        output = IO::Memory.new
        output.write(prefix)
        # RFC 4034 permits the validator to remove duplicate RRs.
        records.map(&.data).uniq!.sort!.each do |data|
          owner.wire(output)
          output.write_bytes(type, Wire::FORMAT)
          output.write_bytes(Wire::IN, Wire::FORMAT)
          output.write_bytes(original_ttl, Wire::FORMAT)
          output.write_bytes(data.size.to_u16, Wire::FORMAT)
          output.write(data)
        end
        output.to_slice
      end
    end

    def supported?(algorithm : UInt8) : Bool
      algorithm.in?({8_u8, 10_u8, 13_u8, 14_u8, 15_u8, 16_u8})
    end

    def verify(key : Key, signature : Bytes, data : Bytes) : Bool
      der = public_key(key)
      return false unless der
      signature = signature_for_openssl(key.algorithm, signature)
      return false unless signature

      input = der.to_unsafe
      LibCrypto.dnssec_clear_errors
      pkey = LibCrypto.dnssec_decode_key(nil, pointerof(input), LibCrypto::Long.new(der.size))
      return false if pkey.null?
      context = LibCrypto.evp_md_ctx_new
      return false if context.null?
      LibCrypto.dnssec_verify_init(context, nil, digest(key.algorithm), nil, pkey) == 1 &&
        LibCrypto.dnssec_verify(context, signature, LibCrypto::SizeT.new(signature.size), data, LibCrypto::SizeT.new(data.size)) == 1
    ensure
      LibCrypto.evp_md_ctx_free(context) if context && !context.null?
      LibCrypto.dnssec_free_key(pkey) if pkey && !pkey.null?
      LibCrypto.dnssec_clear_errors if pkey
    end

    private def signature_for_openssl(algorithm : UInt8, signature : Bytes) : Bytes?
      return signature unless algorithm.in?({13_u8, 14_u8})
      length = algorithm == 13 ? 32 : 48
      return unless signature.size == length * 2
      sequence(integer(signature[0, length]) + integer(signature[length, length]))
    end

    private def digest(algorithm : UInt8) : LibCrypto::EVP_MD
      case algorithm
      when 8, 13 then LibCrypto.evp_sha256
      when 14    then LibCrypto.evp_sha384
      when 10    then LibCrypto.evp_sha512
      else            Pointer(Void).null.as(LibCrypto::EVP_MD) # EdDSA has no external digest.
      end
    end

    private def public_key(key : Key) : Bytes?
      raw = key.material
      case key.algorithm
      when 8, 10
        rsa(raw)
      when 13
        return unless raw.size == 64
        subject_key("301306072a8648ce3d020106082a8648ce3d030107".hexbytes, Bytes[4] + raw)
      when 14
        return unless raw.size == 96
        subject_key("301006072a8648ce3d020106052b81040022".hexbytes, Bytes[4] + raw)
      when 15
        return unless raw.size == 32
        subject_key("300506032b6570".hexbytes, raw)
      when 16
        return unless raw.size == 57
        subject_key("300506032b6571".hexbytes, raw)
      end
    end

    private def rsa(raw : Bytes) : Bytes?
      return if raw.empty?
      exponent_size = raw[0].to_i
      offset = 1
      if exponent_size.zero?
        return if raw.size < 3
        exponent_size = Wire::FORMAT.decode(UInt16, raw[1, 2]).to_i
        offset = 3
      end
      modulus_size = raw.size - offset - exponent_size
      return unless exponent_size.in?(1..8) && modulus_size.in?(128..512)

      exponent = raw[offset, exponent_size]
      modulus = raw[offset + exponent_size..]
      # Reject a padded modulus that would be smaller than 1024 bits.
      return if modulus[0].zero? || (modulus.size == 128 && modulus[0] < 0x80)
      key = sequence(integer(modulus) + integer(exponent))
      subject_key("300d06092a864886f70d0101010500".hexbytes, key)
    end

    private def subject_key(algorithm : Bytes, key : Bytes) : Bytes
      sequence(algorithm + der(3_u8, Bytes[0] + key))
    end

    private def integer(data : Bytes) : Bytes
      offset = 0
      while offset < data.size - 1 && data[offset].zero?
        offset += 1
      end
      value = data[offset..]
      value = Bytes[0] + value if value[0] >= 0x80
      der(2_u8, value)
    end

    private def sequence(data : Bytes) : Bytes
      der(0x30_u8, data)
    end

    private def der(tag : UInt8, data : Bytes) : Bytes
      length = data.size
      prefix =
        if length < 128
          Bytes[tag, length.to_u8]
        elsif length <= 255
          Bytes[tag, 0x81, length.to_u8]
        else
          Bytes[tag, 0x82, (length >> 8).to_u8, (length & 255).to_u8]
        end
      prefix + data
    end
  end
end

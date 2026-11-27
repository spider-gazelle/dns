require "digest/sha1"

module DNS::DNSSEC
  # :nodoc:
  module Denial
    extend self

    record Types, values : Set(UInt16) do
      def self.read(io : IO::Memory) : self
        values = Set(UInt16).new
        previous = -1
        until io.pos == io.size
          window = io.read_bytes(UInt8, Wire::FORMAT).to_i
          size = io.read_bytes(UInt8, Wire::FORMAT).to_i
          raise IO::Error.new("invalid DNSSEC type bitmap") unless window > previous && size.in?(1..32)
          previous = window
          bitmap = Bytes.new(size)
          io.read_fully(bitmap)
          raise IO::Error.new("invalid trailing zero in DNSSEC type bitmap") if bitmap[-1].zero?
          bitmap.each_with_index do |byte, index|
            8.times do |bit|
              values.add((window * 256 + index * 8 + bit).to_u16) if byte.bits_set?(0x80_u8 >> bit)
            end
          end
        end
        new(values)
      end

      def delegation? : Bool
        values.includes?(RecordType::NS.value) && !values.includes?(RecordType::SOA.value)
      end

      def cut? : Bool
        delegation? || values.includes?(RecordType::DNAME.value)
      end

      def denies?(type : UInt16) : Bool
        !values.includes?(type) && !values.includes?(RecordType::CNAME.value)
      end
    end

    struct NSEC
      getter name : Wire::Name
      getter next_name : Wire::Name
      getter types : Types

      def initialize(record : Wire::RR, zone : Wire::Name)
        @name = record.name
        io = IO::Memory.new(record.data)
        @next_name = Wire::Name.read(io, record.data, compression: false)
        @types = Types.read(io)
        if !name.within?(zone) || !next_name.within?(zone) || types.values.empty?
          raise IO::Error.new("NSEC record lies outside its signing zone")
        end
      end

      def covers?(candidate : Wire::Name) : Bool
        return false if types.cut? && candidate.within?(name)
        Denial.between?(name, candidate, next_name)
      end

      def proves_absence?(candidate : Wire::Name) : Bool
        covers?(candidate) && !next_name.within?(candidate)
      end
    end

    record HashParameters, iterations : UInt16, salt : Bytes do
      def hash_name(name : Wire::Name) : String
        buffer = IO::Memory.new
        name.wire(buffer)
        hash = Digest::SHA1.digest(buffer.to_slice + salt)
        iterations.times { hash = Digest::SHA1.digest(hash + salt) }
        Denial.base32hex(hash)
      end
    end

    struct NSEC3
      getter hash_name : String
      getter next_hash : String
      getter types : Types
      getter parameters : HashParameters
      getter? opt_out : Bool

      def initialize(record : Wire::RR, zone : Wire::Name)
        io = IO::Memory.new(record.data)
        algorithm = io.read_bytes(UInt8, Wire::FORMAT)
        flags = io.read_bytes(UInt8, Wire::FORMAT)
        iterations = io.read_bytes(UInt16, Wire::FORMAT)
        if algorithm != 1 || flags > 1 || iterations > 150
          raise ValidationError.new(Status::Indeterminate, "unsupported NSEC3 hash, flags, or iteration count")
        end

        @opt_out = flags == 1
        salt = Bytes.new(io.read_bytes(UInt8, Wire::FORMAT))
        io.read_fully(salt)
        @parameters = HashParameters.new(iterations, salt)
        length = io.read_bytes(UInt8, Wire::FORMAT)
        raise IO::Error.new("invalid NSEC3 hash size") unless length == 20
        hash = Bytes.new(length)
        io.read_fully(hash)
        @hash_name = record.name.labels.first? || ""
        unless record.name.size == zone.size + 1 && record.name.within?(zone) && hash_name.matches?(/\A[0-9a-v]{32}\z/)
          raise IO::Error.new("invalid NSEC3 owner")
        end
        @next_hash = Denial.base32hex(hash)
        @types = Types.read(io)
      end

      def covers?(hash : String) : Bool
        Denial.between?(hash_name, hash, next_hash)
      end
    end

    def between?(first, candidate, last) : Bool
      return false if candidate == first || candidate == last
      first < last ? first < candidate && candidate < last : first < candidate || candidate < last
    end

    private BASE32HEX = "0123456789abcdefghijklmnopqrstuv"

    def base32hex(bytes : Bytes) : String
      String.build do |output|
        value = 0_u16
        bits = 0
        bytes.each do |byte|
          value = (value << 8) | byte
          bits += 8
          while bits >= 5
            bits -= 5
            output.write_byte(BASE32HEX.to_slice[((value >> bits) & 31).to_i])
          end
          value &= (1_u16 << bits) - 1
        end
      end
    end

    # All records passed here have already been authenticated with this zone's keys.
    class Proof
      def initialize(@zone : Wire::Name, records : Array(Wire::RR))
        @nsec = [] of NSEC
        @nsec3 = {} of HashParameters => Array(NSEC3)
        @unsupported = false
        records.each { |record| add(record) }
      end

      private def add(record : Wire::RR) : Nil
        if record.type == RecordType::NSEC.value
          @nsec << NSEC.new(record, @zone)
        elsif record.type == RecordType::NSEC3.value
          proof = NSEC3.new(record, @zone)
          (@nsec3[proof.parameters] ||= [] of NSEC3) << proof
        end
      rescue ValidationError
        @unsupported = true
      end

      def negative(name : Wire::Name, type : UInt16, code : UInt16, *, delegation : Bool = false) : Status?
        result = nsec_negative(name, type, code, delegation)
        return result if result
        @nsec3.each do |parameters, records|
          result = nsec3_negative(name, type, code, delegation, parameters, records)
          return result if result
        end
        unsupported_proof
      end

      def wildcard(name : Wire::Name, closest : Wire::Name) : Status?
        next_closer = name.suffix(closest.size + 1)
        return Status::Secure if @nsec.any?(&.proves_absence?(next_closer))
        @nsec3.each do |parameters, records|
          hash = parameters.hash_name(next_closer)
          if covered = records.find(&.covers?(hash))
            return covered.opt_out? ? Status::Insecure : Status::Secure
          end
        end
        unsupported_proof
      end

      private def unsupported_proof : Status?
        raise ValidationError.new(Status::Indeterminate, "unsupported NSEC3 denial proof") if @unsupported
        nil
      end

      private def exact_status(types : Types, type : UInt16, delegation : Bool) : Status?
        return unless types.denies?(type)
        return Status::Secure unless types.delegation?
        return unless type == RecordType::DS.value
        delegation ? Status::Insecure : Status::Secure
      end

      private def nsec_negative(name : Wire::Name, type : UInt16, code : UInt16, delegation : Bool) : Status?
        return if @nsec.empty?
        if exact = @nsec.find { |record| record.name == name }
          return exact_status(exact.types, type, delegation) if code.zero?
          return
        end

        if code.zero? && @nsec.any? { |record| record.covers?(name) && record.next_name.within?(name) }
          return Status::Secure # Empty nonterminal.
        end

        closest = nsec_closest(name)
        return unless closest && @nsec.any?(&.proves_absence?(name.suffix(closest.size + 1)))
        wildcard = closest.wildcard
        if code == 3
          return Status::Secure if @nsec.any?(&.proves_absence?(wildcard))
        elsif exact = @nsec.find { |record| record.name == wildcard }
          return exact_status(exact.types, type, false)
        end
        nil
      end

      private def nsec_closest(name : Wire::Name) : Wire::Name?
        (name.size - 1).downto(@zone.size) do |count|
          parent = name.suffix(count)
          return if @nsec.any? { |record| record.types.cut? && parent.within?(record.name) }
          return parent if parent == @zone || @nsec.any? { |record| record.name.within?(parent) || record.next_name.within?(parent) }
        end
        nil
      end

      private def nsec3_negative(name : Wire::Name, type : UInt16, code : UInt16, delegation : Bool, parameters : HashParameters, records : Array(NSEC3)) : Status?
        hash = parameters.hash_name(name)
        if exact = records.find { |record| record.hash_name == hash }
          return exact_status(exact.types, type, delegation) if code.zero?
          return
        end

        encloser = nsec3_closest(name, parameters, records)
        return unless encloser
        closest, next_closer_proof = encloser
        if code.zero? && type == RecordType::DS.value && next_closer_proof.opt_out?
          return Status::Insecure
        end
        wildcard_hash = parameters.hash_name(closest.wildcard)
        proved = if code == 3
                   records.any?(&.covers?(wildcard_hash))
                 else
                   records.any? { |record| record.hash_name == wildcard_hash && record.types.denies?(type) && !record.types.cut? }
                 end
        return unless proved
        next_closer_proof.opt_out? ? Status::Insecure : Status::Secure
      end

      private def nsec3_closest(name : Wire::Name, parameters : HashParameters, records : Array(NSEC3)) : {Wire::Name, NSEC3}?
        (name.size - 1).downto(@zone.size) do |count|
          parent = name.suffix(count)
          hash = parameters.hash_name(parent)
          next unless exact = records.find { |record| record.hash_name == hash }
          return if exact.types.cut?
          next_closer = parameters.hash_name(name.suffix(count + 1))
          if covered = records.find(&.covers?(next_closer))
            return {parent, covered}
          end
          return
        end
        nil
      end
    end
  end
end

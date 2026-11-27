# record resources must be of this type
module DNS::Resource
  abstract def initialize(resource_data : Bytes, message : Bytes)

  # :nodoc:
  RESOURCE_STRUCTS = [] of Nil

  macro included
    {% RESOURCE_STRUCTS << @type %}

    macro finished
      def record_type
        RECORD_TYPE
      end
    end
  end

  macro finished
    # :nodoc:
    LOOKUP = {
      {% for resource in RESOURCE_STRUCTS %}
        {% type_code = resource.constant("RECORD_TYPE") %}
        {% raise("#{resource.name} must define RECORD_TYPE") unless type_code %}
        {{ type_code }} => {{ resource.name.id }},
      {% end %}
    }
  end

  # decompress a DNS name starting from the current position an IO::Memory
  def self.read_labels(io : IO::Memory) : String
    read_labels(io, io.to_slice)
  end

  # decompress a DNS name starting from the current position an IO::Memory
  # the entire message must be provided in case this is a pointer to another
  # point in the complete message
  def self.read_labels(io : IO::Memory, message : Bytes, *, allow_compression : Bool = true) : String
    read_name_labels(io, message, allow_compression: allow_compression).join(".")
  end

  # :nodoc:
  def self.read_name_labels(io : IO::Memory, message : Bytes, *, allow_compression : Bool = true) : Array(String)
    labels = [] of String
    pointers = Set(UInt16).new
    wire_size = 1 # root label
    loop do
      length = io.read_byte
      raise IO::EOFError.new if length.nil?
      break if length.zero?

      if length & 0xC0 == 0xC0
        raise IO::Error.new("compressed name is forbidden here") unless allow_compression
        low_byte = io.read_byte
        raise IO::EOFError.new if low_byte.nil?
        pointer = ((length & 0x3F).to_u16 << 8) | low_byte
        unless pointer < message.size && pointers.add?(pointer)
          raise IO::Error.new("invalid DNS name compression pointer")
        end
        io = IO::Memory.new(message)
        io.pos = pointer
      else
        wire_size += 1 + length.to_i
        if length > 63 || wire_size > 255
          raise IO::Error.new("invalid DNS name length")
        end
        labels << io.read_string(length)
      end
    end
    labels
  end

  # :nodoc:
  def self.get_labels_from_pointer(pointer : UInt16, message : Bytes) : String
    raise IO::Error.new("invalid DNS name compression pointer") if pointer >= message.size
    io = IO::Memory.new(message)
    io.pos = pointer
    read_labels(io, message)
  end

  # :nodoc:
  def self.read_type_bitmap(io : IO::Memory) : Set(UInt16)
    types = Set(UInt16).new
    previous = -1
    until io.pos == io.size
      window = io.read_bytes(UInt8).to_i
      size = io.read_bytes(UInt8).to_i
      raise IO::Error.new("invalid DNSSEC type bitmap") unless window > previous && size.in?(1..32)
      previous = window
      bitmap = Bytes.new(size)
      io.read_fully(bitmap)
      raise IO::Error.new("invalid trailing zero in DNSSEC type bitmap") if bitmap[-1].zero?
      bitmap.each_with_index do |byte, index|
        8.times do |bit|
          types.add((window * 256 + index * 8 + bit).to_u16) if byte.bits_set?(0x80_u8 >> bit)
        end
      end
    end
    types
  end

  # :nodoc:
  def self.read_nsec3_parameters(io : IO::Memory) : {UInt8, UInt8, UInt16, Bytes}
    hash_algorithm = io.read_bytes(UInt8)
    flags = io.read_bytes(UInt8)
    iterations = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    salt = Bytes.new(io.read_bytes(UInt8))
    io.read_fully(salt)
    {hash_algorithm, flags, iterations, salt}
  end

  # Writes a name in DNS wire format, including the terminating root label.
  def self.write_labels(io : IO, name : String) : Nil
    name = name.rchop('.')
    unless name.empty?
      labels = name.split('.')
      if labels.any? { |label| label.empty? || label.bytesize > 63 } || name.bytesize > 253
        raise ArgumentError.new("invalid DNS name length")
      end
      labels.each do |label|
        io.write_byte(label.bytesize.to_u8)
        io.write(label.to_slice)
      end
    end
    io.write_byte(0_u8)
  end
end

require "./resource/*"

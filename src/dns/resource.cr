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
        {{type_code}} => {{resource.name.id}},
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
  def self.read_labels(io : IO::Memory, message : Bytes) : String
    labels = [] of String
    loop do
      length = io.read_byte
      break if length.nil?
      break if length.zero?

      if length & 0xC0 == 0xC0
        # Pointer
        pointer = ((length & 0x3F) << 8) | io.read_byte.as(UInt8)
        labels << get_labels_from_pointer(pointer, message)
        break
      else
        labels << io.read_string(length)
      end
    end
    labels.join(".")
  end

  # :nodoc:
  def self.get_labels_from_pointer(pointer : UInt16, message : Bytes) : String
    io = IO::Memory.new(message)
    io.pos = pointer
    read_labels(io, message)
  end
end

require "./resource/*"

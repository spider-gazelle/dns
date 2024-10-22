abstract struct DNS::ResourceRecord::Payload
  abstract def initialize(rdata : Bytes, message : Bytes)

  def self.read_labels(io : IO::Memory) : String
    read_labels(io, io.to_slice)
  end

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

  def self.get_labels_from_pointer(pointer : UInt16, message : Bytes) : String
    io = IO::Memory.new(message)
    io.pos = pointer
    read_labels(io, message)
  end
end

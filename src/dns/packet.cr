struct DNS::Packet
  getter id : UInt16

  getter? response : Bool
  getter operation_code : UInt8

  # AA: Authoritative Answer flag
  getter? authoritative_answer : Bool

  # TC: Truncated flag
  getter? truncation : Bool

  # RD: Recursion Desired flag
  # When set, this field directs the name server to pursue the query recursively.
  getter? recursion_desired : Bool

  # RA: Recursion Available flag
  # In a response, this flag indicates whether the server supports recursion.
  getter? recursion_available : Bool
  getter reserved_z : UInt8 = 0_u8

  # RCODE: Packet code (error indication)
  getter response_code : UInt8

  getter questions : Array(DNS::Packet::Question)
  getter answers : Array(DNS::Packet::ResourceRecord)
  getter authorities : Array(DNS::Packet::ResourceRecord)
  getter additionals : Array(DNS::Packet::ResourceRecord)

  def initialize(
    @id : UInt16,
    flags : UInt16,
    @questions : Array(DNS::Packet::Question),
    @answers : Array(DNS::Packet::ResourceRecord),
    @authorities : Array(DNS::Packet::ResourceRecord),
    @additionals : Array(DNS::Packet::ResourceRecord)
  )
    @response = (flags >> 15) & 0b1 == 1             # QR (1 bit) - Response flag
    @operation_code = ((flags >> 11) & 0b1111).to_u8 # Opcode (4 bits)
    @authoritative_answer = (flags >> 10) & 0b1 == 1 # AA (1 bit) - Authoritative Answer
    @truncation = (flags >> 9) & 0b1 == 1            # TC (1 bit) - Truncation
    @recursion_desired = (flags >> 8) & 0b1 == 1     # RD (1 bit) - Recursion Desired
    @recursion_available = (flags >> 7) & 0b1 == 1   # RA (1 bit) - Recursion Available
    @reserved_z = ((flags >> 4) & 0b111).to_u8       # Z (3 bits) - Reserved (should be 0)
    @response_code = (flags & 0b1111).to_u8          # RCODE (4 bits) - Response Code
  end

  def initialize(
    @id : UInt16,
    @response : Bool = false,
    operation_code : Int | OpCode = OpCode::QUERY,
    @authoritative_answer : Bool = false,
    @truncation : Bool = false,
    @recursion_desired : Bool = true,
    @recursion_available : Bool = false,
    @response_code : UInt8 = 0_u8,
    @questions : Array(DNS::Packet::Question) = [] of DNS::Packet::Question,
    @answers : Array(DNS::Packet::ResourceRecord) = [] of DNS::Packet::ResourceRecord,
    @authorities : Array(DNS::Packet::ResourceRecord) = [] of DNS::Packet::ResourceRecord,
    @additionals : Array(DNS::Packet::ResourceRecord) = [] of DNS::Packet::ResourceRecord
  )
    @operation_code = operation_code.is_a?(Enum) ? operation_code.value : operation_code.to_u8
  end

  def self.from_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    # Extracting the DNS header
    id = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    flags = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

    question_count = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    answer_count = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    authorities_count = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    additionals_count = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

    # Reading the question section
    questions = Array(DNS::Packet::Question).new
    question_count.times do
      questions << io.read_bytes(DNS::Packet::Question)
    end

    # Reading the answer section
    answers = Array(DNS::Packet::ResourceRecord).new
    answer_count.times do
      answers << io.read_bytes(DNS::Packet::ResourceRecord)
    end

    # Reading the authority section
    authorities = Array(DNS::Packet::ResourceRecord).new
    authorities_count.times do
      authorities << io.read_bytes(DNS::Packet::ResourceRecord)
    end

    # Reading the additional section
    additionals = Array(DNS::Packet::ResourceRecord).new
    additionals_count.times do
      additionals << io.read_bytes(DNS::Packet::ResourceRecord)
    end

    DNS::Packet.new(id, flags, questions, answers, authorities, additionals)
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_io(IO::Memory.new(bytes), IO::ByteFormat::BigEndian)
  end

  def to_slice : Bytes
    io = IO::Memory.new
    to_io(io)
    io.to_slice
  end

  def to_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    io.write_bytes(id, IO::ByteFormat::BigEndian)

    qr = @response ? 1_u8 : 0_u8
    aa = @authoritative_answer ? 1_u8 : 0_u8
    tc = @truncation ? 1_u8 : 0_u8
    rd = @recursion_desired ? 1_u8 : 0_u8
    ra = @recursion_available ? 1_u8 : 0_u8
    io.write_byte((qr << 7) | (@operation_code << 3) | (aa << 2) | (tc << 1) | rd)
    io.write_byte((ra << 7) | response_code)

    io.write_bytes(@questions.size.to_u16, IO::ByteFormat::BigEndian)
    io.write_bytes(@answers.size.to_u16, IO::ByteFormat::BigEndian)
    io.write_bytes(@authorities.size.to_u16, IO::ByteFormat::BigEndian)
    io.write_bytes(@additionals.size.to_u16, IO::ByteFormat::BigEndian)

    @questions.each { |question| io.write_bytes(question) }
    @answers.each { |resource_record| io.write_bytes(resource_record) }
    @authorities.each { |resource_record| io.write_bytes(resource_record) }
    @additionals.each { |resource_record| io.write_bytes(resource_record) }
  end

  # QR: Query/Packet flag
  # This field specifies whether this message is a query (0) or a response (1).
  def query? : Bool
    !response?
  end

  # Extract the Opcode from the flags (bits 1 to 4).
  def query_type : OpCode
    OpCode.from_value(operation_code)
  end

  # Check if the response was successful (rcode == 0).
  def success? : Bool
    response_code.zero?
  end

  # Check if there was a server error (rcode == 2).
  def server_error? : Bool
    response_code == 2
  end

  def raise_on_error!
    if question = questions.first?
      message = "Hostname lookup for #{question.name} failed"
    else
      message = "Hostname lookup failed"
    end

    case response_code
    when 1; raise DNS::Packet::FormatError.new(message)
    when 2; raise DNS::Packet::ServerError.new(message)
    when 3; raise DNS::Packet::NameError.new(message)
    when 4; raise DNS::Packet::NotImplementedError.new(message)
    when 5; raise DNS::Packet::RefusedError.new(message)
    end
  end
end

require "./packet/*"

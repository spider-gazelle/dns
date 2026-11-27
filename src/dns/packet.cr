struct DNS::Packet
  # the transaction id. settable so the shared UDP transport can remap a
  # response's wire id back to the caller's logical request id.
  property id : UInt16

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
  # The original three-bit Z field, including the AD and CD bits.
  getter reserved_z : UInt8 = 0_u8

  # RCODE: Packet code (error indication)
  getter response_code : UInt8

  getter questions : Array(DNS::Packet::Question)
  getter answers : Array(DNS::Packet::ResourceRecord)
  getter authorities : Array(DNS::Packet::ResourceRecord)
  getter additionals : Array(DNS::Packet::ResourceRecord)
  getter edns : EDNS?

  def initialize(
    @id : UInt16,
    flags : UInt16,
    @questions : Array(DNS::Packet::Question),
    @answers : Array(DNS::Packet::ResourceRecord),
    @authorities : Array(DNS::Packet::ResourceRecord),
    @additionals : Array(DNS::Packet::ResourceRecord),
  )
    @response = (flags >> 15) & 0b1 == 1             # QR (1 bit) - Response flag
    @operation_code = ((flags >> 11) & 0b1111).to_u8 # Opcode (4 bits)
    @authoritative_answer = (flags >> 10) & 0b1 == 1 # AA (1 bit) - Authoritative Answer
    @truncation = (flags >> 9) & 0b1 == 1            # TC (1 bit) - Truncation
    @recursion_desired = (flags >> 8) & 0b1 == 1     # RD (1 bit) - Recursion Desired
    @recursion_available = (flags >> 7) & 0b1 == 1   # RA (1 bit) - Recursion Available
    @reserved_z = ((flags >> 4) & 0b111).to_u8       # Z, AD, CD
    @response_code = (flags & 0b1111).to_u8          # RCODE (4 bits) - Response Code
    @edns = EDNS.from_additionals(@additionals)
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
    @additionals : Array(DNS::Packet::ResourceRecord) = [] of DNS::Packet::ResourceRecord,
    *,
    authenticated_data : Bool = false,
    checking_disabled : Bool = false,
  )
    @operation_code = operation_code.is_a?(Enum) ? operation_code.value : operation_code.to_u8
    @reserved_z |= 0b010_u8 if authenticated_data
    @reserved_z |= 0b001_u8 if checking_disabled
    @edns = EDNS.from_additionals(@additionals)
  end

  # Reads a single DNS message from the remaining bytes of the IO.
  def self.from_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_slice(io.getb_to_end, format)
  end

  def self.from_io(io : IO::Memory, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    return read_message(io) if io.pos.zero?

    message = IO::Memory.new(io.to_slice[io.pos..])
    packet = read_message(message)
    io.pos += message.pos
    packet
  end

  private def self.read_message(io : IO::Memory) : self
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

    answers = read_records(io, answer_count)
    authorities = read_records(io, authorities_count)
    additionals = read_records(io, additionals_count)

    DNS::Packet.new(id, flags, questions, answers, authorities, additionals)
  end

  private def self.read_records(io : IO::Memory, count : UInt16) : Array(ResourceRecord)
    records = Array(ResourceRecord).new
    malformed : Set({String, UInt16, UInt16})? = nil
    count.times do
      record = io.read_bytes(ResourceRecord)
      records << record
      if record.resource.nil? && record.type.in?({RecordType::SVCB.value, RecordType::HTTPS.value})
        (malformed ||= Set({String, UInt16, UInt16}).new) << {record.name.downcase, record.type, record.class_code}
      end
    end
    if rejected = malformed
      records.reject! { |record| rejected.includes?({record.name.downcase, record.type, record.class_code}) }
    end
    records
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    read_message(IO::Memory.new(bytes))
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
    io.write_byte((ra << 7) | (reserved_z << 4) | response_code)

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

  # The AD bit received from the upstream. Interpret it only for a trusted
  # upstream reached over an authenticated transport.
  def authenticated_data? : Bool
    reserved_z.bits_set?(0b010_u8)
  end

  def checking_disabled? : Bool
    reserved_z.bits_set?(0b001_u8)
  end

  # Extract the Opcode from the flags (bits 1 to 4).
  def query_type : OpCode
    OpCode.from_value(operation_code)
  end

  # Check if the response was successful (rcode == 0).
  def success? : Bool
    effective_response_code.zero?
  end

  # Check if there was a server error (rcode == 2).
  def server_error? : Bool
    effective_response_code == 2
  end

  # Combines the header's four bits with the eight extended RCODE bits in OPT.
  def effective_response_code : UInt16
    if opt = edns
      (opt.extended_rcode.to_u16 << 4) | response_code
    else
      response_code.to_u16
    end
  end

  # A legacy server can signal that it cannot process EDNS without an OPT reply.
  def edns_rejected? : Bool
    code = effective_response_code
    code == 16 || (code.in?({1, 4}) && edns.nil?)
  end

  def extended_errors : Array(EDNS::ExtendedError)
    edns.try(&.extended_errors) || [] of EDNS::ExtendedError
  end

  # Validates a reply to a single Internet-class QUERY.
  def matches_question?(domain : String, type : UInt16, id : UInt16, *, allow_missing_question : Bool = false) : Bool
    return false unless response? && @id == id && operation_code == OpCode::QUERY.value
    return allow_missing_question if questions.empty?
    return false unless questions.size == 1

    question = questions.first
    question.type == type && question.class_code == ClassCode::Internet.value &&
      question.name.compare(domain.rchop('.'), case_insensitive: true) == 0
  end

  def raise_on_error!
    code = effective_response_code
    return if code.zero?

    if question = questions.first?
      message = "Hostname lookup for #{question.name} failed"
    else
      message = "Hostname lookup failed"
    end

    error = case code
            when 1 then DNS::Packet::FormatError.new(message)
            when 2 then DNS::Packet::ServerError.new(message)
            when 3 then DNS::Packet::NameError.new(message)
            when 4 then DNS::Packet::NotImplementedError.new(message)
            when 5 then DNS::Packet::RefusedError.new(message)
            else        DNS::Packet::ResponseError.new(message, code)
            end
    error.extended_errors = extended_errors
    raise error
  end
end

require "./packet/*"

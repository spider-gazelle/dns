struct DNS::Response
  property id : UInt16
  property flags : UInt16
  property qdcount : UInt16
  property ancount : UInt16
  property nscount : UInt16
  property arcount : UInt16
  property questions : Array(DNS::Question)
  property answers : Array(DNS::ResourceRecord)
  property authorities : Array(DNS::ResourceRecord)
  property additionals : Array(DNS::ResourceRecord)

  def initialize(
    @id : UInt16,
    @flags : UInt16,
    @qdcount : UInt16,
    @ancount : UInt16,
    @nscount : UInt16,
    @arcount : UInt16,
    @questions : Array(DNS::Question),
    @answers : Array(DNS::ResourceRecord),
    @authorities : Array(DNS::ResourceRecord),
    @additionals : Array(DNS::ResourceRecord)
  )
  end

  def self.from_io(io : IO, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    # Extracting the DNS header
    id = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    flags = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    qdcount = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    ancount = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    nscount = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    arcount = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)

    # Reading the question section
    questions = Array(DNS::Question).new
    qdcount.times do
      name = DNS::ResourceRecord::Payload.read_labels(io)
      type = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      class_code = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      question = DNS::Question.new(name, type, class_code)
      questions << question
    end

    # Reading the answer section
    answers = Array(DNS::ResourceRecord).new
    ancount.times do
      answers << io.read_bytes(DNS::ResourceRecord)
    end

    # Reading the authority section
    authorities = Array(DNS::ResourceRecord).new
    nscount.times do
      authorities << io.read_bytes(DNS::ResourceRecord)
    end

    # Reading the additional section
    additionals = Array(DNS::ResourceRecord).new
    arcount.times do
      additionals << io.read_bytes(DNS::ResourceRecord)
    end

    DNS::Response.new(id, flags, qdcount, ancount, nscount, arcount, questions, answers, authorities, additionals)
  end

  def self.from_slice(bytes : Bytes, format : IO::ByteFormat = IO::ByteFormat::BigEndian)
    from_io(IO::Memory.new(bytes), IO::ByteFormat::BigEndian)
  end

  # QR: Query/Response flag
  # This field specifies whether this message is a query (0) or a response (1).
  def query? : Bool
    (@flags & 0x8000) == 0
  end

  def response? : Bool
    (@flags & 0x8000) != 0
  end

  # Opcode: Specifies the kind of query in this message.
  enum OpCode
    QUERY  = 0 # a standard query
    IQUERY = 1 # an inverse query
    STATUS = 2 # a server status request
  end

  # Extract the Opcode from the flags (bits 1 to 4).
  def query_type : OpCode
    OpCode.from_value((@flags >> 11) & 0x0F)
  end

  # AA: Authoritative Answer flag
  # This field is valid in responses, and specifies that the responding server is authoritative.
  def authoritative? : Bool
    (@flags & 0x0400) != 0
  end

  # TC: Truncated flag
  # This flag indicates that the message was truncated due to length greater than allowed on the transmission channel.
  def truncated? : Bool
    (@flags & 0x0200) != 0
  end

  # RD: Recursion Desired flag
  # When set, this field directs the name server to pursue the query recursively.
  def recursion_desired? : Bool
    (@flags & 0x0100) != 0
  end

  # RA: Recursion Available flag
  # In a response, this flag indicates whether the server supports recursion.
  def recursion_available? : Bool
    (@flags & 0x0080) != 0
  end

  # Z: Reserved for future use (must be zero).
  def reserved_z? : Bool
    (@flags & 0x0070) == 0
  end

  # RCODE: Response code (part of the flags)
  # Extracted from bits 0 to 3 of the flags.
  def response_code : UInt8
    (@flags & 0x000F).to_u8
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
    case response_code
    when 1; raise DNS::Response::FormatError.new
    when 2; raise DNS::Response::ServerError.new
    when 3; raise DNS::Response::NameError.new
    when 4; raise DNS::Response::NotImplementedError.new
    when 5; raise DNS::Response::RefusedError.new
    end
  end
end

require "./response/*"

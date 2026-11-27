require "../resource"

# Shared wire format for SVCB and HTTPS records (RFC 9460).
module DNS::Resource::ServiceBinding
  MANDATORY       = 0_u16
  ALPN            = 1_u16
  NO_DEFAULT_ALPN = 2_u16
  PORT            = 3_u16
  IPV4_HINT       = 4_u16
  IPV6_HINT       = 6_u16
  SUPPORTED_KEYS  = {ALPN, NO_DEFAULT_ALPN, PORT, IPV4_HINT, IPV6_HINT}

  getter priority : UInt16
  getter target_name : String
  getter alpn = [] of String
  getter svcparam = {} of UInt16 => Bytes
  getter mandatory_keys = [] of UInt16
  getter? no_default_alpn = false
  getter port : UInt16? = nil
  getter ipv4_hints = [] of Socket::IPAddress
  getter ipv6_hints = [] of Socket::IPAddress

  def initialize(resource_data : Bytes, message : Bytes)
    io = IO::Memory.new(resource_data)
    @priority = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
    @target_name = Resource.read_labels(io, message, allow_compression: false)

    previous : UInt16? = nil
    until io.pos == io.size
      key = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      raise IO::Error.new("unordered service binding parameters") if previous && key <= previous
      previous = key
      length = io.read_bytes(UInt16, IO::ByteFormat::BigEndian)
      value = Bytes.new(length)
      io.read_fully(value)
      @svcparam[key] = value unless key == ALPN
      parse_parameter(key, value) if service_mode?
    end

    validate_mandatory_keys if service_mode?
  end

  def alias_mode? : Bool
    priority.zero?
  end

  def service_mode? : Bool
    !alias_mode?
  end

  # Pass the keys the caller can honor when using this record.
  def compatible?(supported_keys : Enumerable(UInt16) = SUPPORTED_KEYS) : Bool
    return true if alias_mode?
    mandatory_keys.all? { |key| supported_keys.includes?(key) } &&
      automatically_mandatory_keys.all? { |key| !svcparam.has_key?(key) || supported_keys.includes?(key) }
  end

  protected def automatically_mandatory_keys : Enumerable(UInt16)
    [] of UInt16
  end

  private def parse_parameter(key : UInt16, value : Bytes) : Nil
    case key
    when MANDATORY
      if value.empty? || value.size.odd?
        raise IO::Error.new("invalid mandatory service binding parameter")
      end
      (0...value.size).step(2) { |index| @mandatory_keys << IO::ByteFormat::BigEndian.decode(UInt16, value[index, 2]) }
    when ALPN
      parse_alpn(value)
    when NO_DEFAULT_ALPN
      raise IO::Error.new("invalid no-default-alpn parameter") unless value.empty?
      @no_default_alpn = true
    when PORT
      raise IO::Error.new("invalid service binding port") unless value.size == 2
      @port = IO::ByteFormat::BigEndian.decode(UInt16, value)
    when IPV4_HINT
      @ipv4_hints = parse_hints(value, Resource::A, 4)
    when IPV6_HINT
      @ipv6_hints = parse_hints(value, Resource::AAAA, 16)
    end
  end

  private def parse_hints(value : Bytes, address_type, width : Int32) : Array(Socket::IPAddress)
    raise IO::Error.new("invalid service binding address hints") if value.empty? || value.size % width != 0
    (0...value.size).step(width).map { |index| address_type.new(value[index, width], value).to_ip }.to_a
  end

  private def parse_alpn(value : Bytes) : Nil
    raise IO::Error.new("empty service binding ALPN parameter") if value.empty?
    io = IO::Memory.new(value)
    until io.pos == io.size
      size = io.read_byte || raise IO::EOFError.new
      raise IO::Error.new("empty ALPN identifier") if size.zero?
      @alpn << io.read_string(size)
    end
  end

  private def validate_mandatory_keys : Nil
    previous = MANDATORY
    mandatory_keys.each do |key|
      present = key == ALPN ? !alpn.empty? : svcparam.has_key?(key)
      raise IO::Error.new("invalid mandatory service binding key") if key <= previous || !present
      previous = key
    end
    raise IO::Error.new("no-default-alpn requires alpn") if no_default_alpn? && alpn.empty?
  end
end

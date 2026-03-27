require "socket"

class Socket
  def self.extract_win_ip_address(sockaddr_ptr : UInt8*, sockaddr_len : Int32) : String?
    sockaddr_family = sockaddr_ptr.as(LibC::Sockaddr*).value.sa_family

    case sockaddr_family
    when LibC::AF_INET
      Socket::IPAddress.new(sockaddr_ptr.as(LibC::SockaddrIn*), sockaddr_len).address
    when LibC::AF_INET6
      Socket::IPAddress.new(sockaddr_ptr.as(LibC::SockaddrIn6*), sockaddr_len).address
    else
      nil
    end
  end
end

require "crystal/system/win32/windows_registry"

class DNS::Servers
  @[Link("iphlpapi")]
  lib IpHlpApi
    # Constants for GetAdaptersAddresses flags
    GAA_FLAG_SKIP_ANYCAST    = 0x00000002_u32
    GAA_FLAG_SKIP_MULTICAST  = 0x00000004_u32
    GAA_FLAG_SKIP_DNS_SERVER = 0x00000008_u32
    GAA_FLAG_INCLUDE_PREFIX  = 0x00000010_u32

    # Other necessary constants
    ERROR_BUFFER_OVERFLOW = 111_u32
    ERROR_SUCCESS         =   0_u32

    # https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-socket_address
    struct SOCKET_ADDRESS
      lp_sockaddr : UInt8*
      i_sockaddr_length : LibC::Int
    end

    # https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_dns_server_address_xp
    struct IP_ADAPTER_DNS_SERVER_ADDRESS
      length : LibC::ULong
      reserved : LibC::DWORD
      next_ip : IP_ADAPTER_DNS_SERVER_ADDRESS*
      address : SOCKET_ADDRESS
    end

    # https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh
    struct IP_ADAPTER_ADDRESSES
      length : LibC::ULong
      if_index : UInt32
      next_adapter : IP_ADAPTER_ADDRESSES*
      adapter_name : UInt8*
      first_unicast_address : Void*
      first_anycast_address : Void*
      first_multicast_address : Void*
      first_dns_server_address : IP_ADAPTER_DNS_SERVER_ADDRESS*
      # Other fields omitted for brevity
    end

    # https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
    fun GetAdaptersAddresses(family : LibC::ULong, flags : LibC::DWORD, reserved : Void*, addresses : IP_ADAPTER_ADDRESSES*, size : UInt32*) : LibC::DWORD
  end

  # Read DNS search list from Windows registry
  private def self.read_search_list_from_registry : Array(String)
    search = [] of String

    # Open the TCPIP Parameters key
    reg_path = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters".to_utf16
    Crystal::System::WindowsRegistry.open?(LibC::HKEY_LOCAL_MACHINE, reg_path) do |key|
      # Try to read SearchList value (comma-separated list of domains)
      value_name = "SearchList".to_utf16
      if search_string = Crystal::System::WindowsRegistry.get_string(key, value_name)
        search = search_string.split(',').map(&.strip).reject(&.empty?)
      end
    end

    search
  rescue
    [] of String
  end

  # Extract DNS servers from network adapters
  private def self.dns_servers_from_adapters : Array(String)
    dns_servers = [] of String

    family = LibC::AF_UNSPEC
    flags = IpHlpApi::GAA_FLAG_SKIP_ANYCAST | IpHlpApi::GAA_FLAG_SKIP_MULTICAST

    size = UInt32.new(15_000) # Initial buffer size
    buffer = Pointer(UInt8).malloc(size)

    result = IpHlpApi.GetAdaptersAddresses(family, flags, nil, buffer.as(IpHlpApi::IP_ADAPTER_ADDRESSES*), pointerof(size))

    if result == IpHlpApi::ERROR_BUFFER_OVERFLOW
      # Reallocate buffer with the required size
      buffer = Pointer(UInt8).malloc(size)
      result = IpHlpApi.GetAdaptersAddresses(family, flags, nil, buffer.as(IpHlpApi::IP_ADAPTER_ADDRESSES*), pointerof(size))
    end

    if result == IpHlpApi::ERROR_SUCCESS
      adapter = buffer.as(IpHlpApi::IP_ADAPTER_ADDRESSES*)

      while !adapter.null?
        dns_address = adapter.value.first_dns_server_address

        while !dns_address.null?
          sockaddr = dns_address.value.address.lp_sockaddr
          sockaddr_len = dns_address.value.address.i_sockaddr_length

          ip = Socket.extract_win_ip_address(sockaddr, sockaddr_len)
          dns_servers << ip if ip

          dns_address = dns_address.value.next_ip
        end

        adapter = adapter.value.next_adapter
      end
    else
      Log.trace { "GetAdaptersAddresses failed with error code: #{result}" }
    end

    dns_servers.uniq
  end

  # Load DNS configuration from Windows APIs
  # Returns: {servers, search_domains, ndots}
  protected def self.load_system_config : Tuple(Array(String), Array(String), Int32)
    servers = dns_servers_from_adapters
    search = read_search_list_from_registry
    ndots = 1 # Windows default

    {servers, search, ndots}
  rescue ex
    Log.warn(exception: ex) { "failed to parse Windows DNS configuration" }
    {[] of String, [] of String, 1}
  end
end

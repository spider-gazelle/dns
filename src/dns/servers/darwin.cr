class DNS::Servers
  @[Link(framework: "CoreFoundation")]
  @[Link(framework: "SystemConfiguration")]
  lib LibSystemConfiguration
    # Type definitions
    alias CFIndex = LibC::Long
    alias CFStringRef = UInt8*
    alias CFArrayRef = Void*
    alias CFDictionaryRef = Void*
    alias CFAllocatorRef = Void*
    alias CFTypeRef = Void*
    alias SCDynamicStoreRef = Void*
    alias CFStringEncoding = UInt32

    # Constants
    CFStringEncodingUTF8 = 0x08000100_u32

    # Function declarations
    fun CFStringCreateWithCString(alloc : CFAllocatorRef, cStr : UInt8*, encoding : CFStringEncoding) : CFStringRef
    fun CFStringGetCString(theString : CFStringRef, buffer : UInt8*, bufferSize : LibC::Long, encoding : CFStringEncoding) : Bool

    fun SCDynamicStoreCreate(allocator : CFAllocatorRef, name : CFStringRef, callback : Void*, context : Void*) : SCDynamicStoreRef
    fun SCDynamicStoreCopyValue(store : SCDynamicStoreRef, key : CFStringRef) : CFDictionaryRef

    fun CFDictionaryGetValue(theDict : CFDictionaryRef, key : CFStringRef) : CFTypeRef
    fun CFArrayGetCount(theArray : CFArrayRef) : CFIndex
    fun CFArrayGetValueAtIndex(theArray : CFArrayRef, idx : CFIndex) : CFTypeRef

    fun CFRelease(cf : CFTypeRef)
  end

  # Helper method to create a CFString from a Crystal String
  private def self.create_cfstring(str : String) : LibSystemConfiguration::CFStringRef
    cstr = str.to_unsafe
    LibSystemConfiguration.CFStringCreateWithCString(nil, cstr, LibSystemConfiguration::CFStringEncodingUTF8)
  end

  # Helper to extract string array from CFArray
  private def self.extract_string_array(array_ref : Void*) : Array(String)
    result = [] of String
    return result if array_ref.null?

    count = LibSystemConfiguration.CFArrayGetCount(array_ref)
    (0...count).each do |i|
      cf_str = LibSystemConfiguration.CFArrayGetValueAtIndex(array_ref, i)
      buffer = Bytes.new(256)
      success = LibSystemConfiguration.CFStringGetCString(cf_str.as(UInt8*), buffer.to_unsafe, buffer.size, LibSystemConfiguration::CFStringEncodingUTF8)
      if success
        end_of_string = buffer.index(0_u8)
        result << String.new(buffer[0...end_of_string])
      end
    end
    result
  end

  # Load DNS configuration from SystemConfiguration framework
  # Returns: {servers, search_domains, ndots}
  protected def self.load_system_config : Tuple(Array(String), Array(String), Int32)
    servers = [] of String
    search = [] of String
    ndots = 1 # macOS default

    # Create a dynamic store reference
    store_name = create_cfstring("crystal_app")
    store = LibSystemConfiguration.SCDynamicStoreCreate(nil, store_name, nil, nil)
    LibSystemConfiguration.CFRelease(store_name)

    # Define the key for DNS configuration
    dns_key = create_cfstring("State:/Network/Global/DNS")
    dns_dict = LibSystemConfiguration.SCDynamicStoreCopyValue(store, dns_key)
    LibSystemConfiguration.CFRelease(dns_key)
    LibSystemConfiguration.CFRelease(store)

    if dns_dict.null?
      Log.trace { "no DNS configuration found" }
      return {servers, search, ndots}
    end

    # Get the array of DNS server addresses
    server_addresses_key = create_cfstring("ServerAddresses")
    server_addresses_ref = LibSystemConfiguration.CFDictionaryGetValue(dns_dict, server_addresses_key)
    LibSystemConfiguration.CFRelease(server_addresses_key)

    unless server_addresses_ref.null?
      servers = extract_string_array(server_addresses_ref.as(Void*))
    end

    # Get the array of search domains
    search_domains_key = create_cfstring("SearchDomains")
    search_domains_ref = LibSystemConfiguration.CFDictionaryGetValue(dns_dict, search_domains_key)
    LibSystemConfiguration.CFRelease(search_domains_key)

    unless search_domains_ref.null?
      search = extract_string_array(search_domains_ref.as(Void*))
    end

    LibSystemConfiguration.CFRelease(dns_dict)
    {servers, search, ndots}
  rescue ex
    Log.warn(exception: ex) { "failed to parse DNS configuration" }
    {[] of String, [] of String, 1}
  end
end

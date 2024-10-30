module DNS::Servers
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
  def self.create_cfstring(str : String) : LibSystemConfiguration::CFStringRef
    cstr = str.to_unsafe
    LibSystemConfiguration.CFStringCreateWithCString(nil, cstr, LibSystemConfiguration::CFStringEncodingUTF8)
  end

  # Main method to get DNS servers
  class_getter from_host : Array(String) do
    dns_servers = [] of String

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
      return dns_servers
    end

    # Get the array of DNS server addresses
    server_addresses_key = create_cfstring("ServerAddresses")
    server_addresses_ref = LibSystemConfiguration.CFDictionaryGetValue(dns_dict, server_addresses_key)
    LibSystemConfiguration.CFRelease(server_addresses_key)

    if server_addresses_ref.null?
      Log.trace { "no DNS server addresses found in store" }
      LibSystemConfiguration.CFRelease(dns_dict)
      return dns_servers
    end

    # Cast the CFTypeRef to CFArrayRef
    server_addresses_array = server_addresses_ref.as(Void*)
    count = LibSystemConfiguration.CFArrayGetCount(server_addresses_array)

    # Iterate over the array and print DNS server addresses
    (0...count).each do |i|
      cf_str = LibSystemConfiguration.CFArrayGetValueAtIndex(server_addresses_array, i)
      buffer = Bytes.new(256)
      success = LibSystemConfiguration.CFStringGetCString(cf_str.as(UInt8*), buffer.to_unsafe, buffer.size, LibSystemConfiguration::CFStringEncodingUTF8)
      if success
        end_of_string = buffer.index(0_u8)
        dns_servers << String.new(buffer[0...end_of_string])
      end
    end

    LibSystemConfiguration.CFRelease(dns_dict)
    dns_servers
  rescue ex
    Log.warn(exception: ex) { "failed to parse DNS configuration" }
    [] of String
  end
end

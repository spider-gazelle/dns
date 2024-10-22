module DNS::Option
  # Mapping of known option codes to their names
  OPTION_CODE_NAMES = {
     8 => "EDNS Client Subnet (ECS)",
     9 => "EDNS EXPIRE",
    10 => "EDNS COOKIE",
    11 => "EDNS TCP KEEPALIVE",
    12 => "EDNS PADDING",
    15 => "EDNS Key Tag",
  }

  # IPv4 rdata parser
  ResourceRecord.register_parser(RecordCode::OPT) do |rdata, _message|
    options = ResourceRecord::ParsedData.new
    index = 0

    while index < rdata.size
      # Ensure that there are at least 4 bytes to read the option code and length
      if index + 4 > rdata.size
        raise "Incomplete OPT record data at index #{index}"
      end

      # Read option code (2 bytes, big-endian)
      option_code = (rdata[index].to_u16 << 8) | rdata[index + 1].to_u16
      index += 2

      # Read option length (2 bytes, big-endian)
      option_length = (rdata[index].to_u16 << 8) | rdata[index + 1].to_u16
      index += 2

      # Ensure the option data is within the bounds of rdata
      if index + option_length > rdata.size
        raise "Option length exceeds RDATA size at index #{index}"
      end

      # Read option data
      option_data = rdata[index, option_length]
      index += option_length

      # Get the option name or default to "OPTION-<code>"
      option_name = OPTION_CODE_NAMES[option_code] || "OPTION-#{option_code}"

      # Parse known option codes
      case option_code
      when 8 # EDNS Client Subnet (ECS)
        if option_length >= 4
          family = (option_data[0].to_u16 << 8) | option_data[1].to_u16
          source_prefix_length = option_data[2]
          scope_prefix_length = option_data[3]
          address_length = (source_prefix_length + 7) // 8 # Ceiling division
          address_bytes = option_data[4, address_length]

          ip_address = case family
                       when 1 # IPv4
                         address_bytes.map(&.to_s).join(".")
                       when 2 # IPv6
                         address_bytes.each_slice(2).map { |bytes|
                           ((bytes[0].to_u16 << 8) | bytes[1].to_u16).to_s(16)
                         }.join(":")
                       else
                         "Unknown family #{family}"
                       end

          options[option_name] = "Family: #{family}, Source Prefix Length: #{source_prefix_length}, " +
                                 "Scope Prefix Length: #{scope_prefix_length}, Address: #{ip_address}"
        else
          options[option_name] = "Invalid ECS option data"
        end
      when 12 # EDNS Padding
        # Padding bytes are typically zeros; represent the length
        options[option_name] = option_length.to_i64
      else
        # For unknown options, store the hexadecimal representation of the data
        options[option_name] = "Data: #{option_data.hexstring}"
      end
    end

    options
  end
end

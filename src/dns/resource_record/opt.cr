module DNS
  struct ResourceRecord::OPT < ResourceRecord::Payload
    getter ecs_family : UInt16? = nil
    getter ecs_source_prefix_length : UInt8? = nil
    getter ecs_scope_prefix_length : UInt8? = nil
    getter ecs_address : String? = nil
    getter edns_padding_length : UInt64? = nil
    getter options : Hash(UInt16, Bytes)

    def initialize(rdata : Bytes, message : Bytes)
      @options = {} of UInt16 => Bytes

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

        # Handle known option codes
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

            @ecs_family = family
            @ecs_source_prefix_length = source_prefix_length
            @ecs_scope_prefix_length = scope_prefix_length
            @ecs_address = ip_address
          else
            # Invalid ECS option data
            @ecs_family = nil
            @ecs_source_prefix_length = nil
            @ecs_scope_prefix_length = nil
            @ecs_address = nil
          end
        when 12 # EDNS Padding
          # Padding bytes are typically zeros; represent the length
          @edns_padding_length = option_length.to_u64
        else
          # For unknown options, store the data
          @options[option_code] = option_data
        end
      end
    end
  end

  ResourceRecord.register_record(RecordCode::OPT, ResourceRecord::OPT)
end

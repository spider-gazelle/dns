module DNS
  # IPv4 rdata parser
  ResourceRecord.register_parser(RecordCode::A) do |rdata, _message|
    ip_str = rdata.map(&.to_s).join(".")
    ResourceRecord::ParsedData{"address" => ip_str}
  end

  # IPv6 rdata parser
  ResourceRecord.register_parser(RecordCode::AAAA) do |rdata, _message|
    ip_str = rdata.each_slice(2).map { |bytes|
      ((bytes[0].to_u16 << 8) | bytes[1].to_u16).to_s(16)
    }.join(":")
    ResourceRecord::ParsedData{"address" => ip_str}
  end
end

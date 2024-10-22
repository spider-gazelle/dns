module DNS
  struct ResourceRecord::AAAA < ResourceRecord::Payload
    property address : String

    def initialize(rdata : Bytes, message : Bytes)
      @address = rdata.each_slice(2).map { |bytes|
        ((bytes[0].to_u16 << 8) | bytes[1].to_u16).to_s(16)
      }.join(":")
    end
  end

  ResourceRecord.register_record(RecordCode::AAAA, ResourceRecord::AAAA)
end

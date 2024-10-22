module DNS
  struct ResourceRecord::A < ResourceRecord::Payload
    property address : String

    def initialize(rdata : Bytes, message : Bytes)
      @address = rdata.map(&.to_s).join(".")
    end
  end

  ResourceRecord.register_record(RecordCode::A, ResourceRecord::A)
end

module DNS
  # PTR record parsing
  struct ResourceRecord::PTR < ResourceRecord::Payload
    getter domain_name : String

    def initialize(rdata : Bytes, message : Bytes)
      # PTR records contain a single domain name, which is the target of the reverse DNS lookup.
      @domain_name = ResourceRecord::Payload.read_labels(IO::Memory.new(rdata), message)
    end
  end

  ResourceRecord.register_record(RecordCode::PTR, ResourceRecord::PTR)
end

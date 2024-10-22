module DNS
  # CNAME record parsing
  struct ResourceRecord::CNAME < ResourceRecord::Payload
    getter target : String

    def initialize(rdata : Bytes, message : Bytes)
      # The CNAME record contains a single domain name, so we parse it using the label-reading method.
      @target = ResourceRecord::Payload.read_labels(IO::Memory.new(rdata), message)
    end
  end

  ResourceRecord.register_record(RecordCode::CNAME, ResourceRecord::CNAME)
end

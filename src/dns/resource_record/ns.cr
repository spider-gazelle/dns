module DNS
  # NS record parsing
  struct ResourceRecord::NS < ResourceRecord::Payload
    getter name_server : String

    def initialize(rdata : Bytes, message : Bytes)
      # NS records contain a single domain name, which represents the name server.
      @name_server = ResourceRecord::Payload.read_labels(IO::Memory.new(rdata), message)
    end
  end

  ResourceRecord.register_record(RecordCode::NS, ResourceRecord::NS)
end

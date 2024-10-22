module DNS
  struct Resource::AAAA < Resource
    getter address : String

    def initialize(resource_data : Bytes, message : Bytes)
      @address = resource_data.each_slice(2).map { |bytes|
        ((bytes[0].to_u16 << 8) | bytes[1].to_u16).to_s(16)
      }.join(":")
    end
  end

  Resource.register_record(RecordCode::AAAA, Resource::AAAA)
end

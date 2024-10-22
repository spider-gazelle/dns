module DNS
  struct Resource::A < Resource
    getter address : String

    def initialize(resource_data : Bytes, message : Bytes)
      @address = resource_data.map(&.to_s).join(".")
    end
  end

  Resource.register_record(RecordCode::A, Resource::A)
end

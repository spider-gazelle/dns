require "./service_binding"

module DNS
  struct Resource::SVCB
    include Resource
    include Resource::ServiceBinding

    RECORD_TYPE = 64_u16
  end
end

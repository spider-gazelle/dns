require "./service_binding"

module DNS
  struct Resource::HTTPS
    include Resource
    include Resource::ServiceBinding

    RECORD_TYPE = 65_u16

    protected def automatically_mandatory_keys : Enumerable(UInt16)
      {NO_DEFAULT_ALPN, PORT}
    end
  end
end

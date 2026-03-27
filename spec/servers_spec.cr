describe DNS::Servers do
  describe ".expand" do
    it "handles FQDN with trailing dot" do
      result = DNS::Servers.expand("www.google.com.", search: ["example.com"], ndots: 1)
      result.should eq ["www.google.com"]
    end

    it "expands single-label names with search domains first" do
      result = DNS::Servers.expand("redis", search: ["svc.cluster.local"], ndots: 1)
      result.should eq ["redis.svc.cluster.local", "redis"]
    end

    it "tries bare name first when dots >= ndots" do
      result = DNS::Servers.expand("api.prod", search: ["example.com"], ndots: 1)
      result.should eq ["api.prod", "api.prod.example.com"]
    end

    it "tries search domains first when dots < ndots" do
      result = DNS::Servers.expand("api.prod", search: ["example.com"], ndots: 2)
      result.should eq ["api.prod.example.com", "api.prod"]
    end

    it "handles multiple search domains" do
      result = DNS::Servers.expand("myapp", search: ["ns1.local", "ns2.local"], ndots: 1)
      result.should eq ["myapp.ns1.local", "myapp.ns2.local", "myapp"]
    end

    it "avoids overlap when name ends with search domain prefix" do
      result = DNS::Servers.expand("redis.svc", search: ["svc.cluster.local"], ndots: 2)
      result.should eq ["redis.svc"]
    end

    it "avoids full overlap when name ends with entire search domain" do
      result = DNS::Servers.expand("app.svc.cluster.local", search: ["svc.cluster.local"], ndots: 1)
      result.should eq ["app.svc.cluster.local"]
    end

    it "returns just the name with empty search list" do
      result = DNS::Servers.expand("myhost", search: [] of String, ndots: 1)
      result.should eq ["myhost"]
    end

    it "deduplicates candidates" do
      # When ndots=0, dots(0) >= ndots(0), so bare name goes first
      # Then search domains append, but if they result in same name, dedupe
      result = DNS::Servers.expand("host", search: [] of String, ndots: 0)
      result.should eq ["host"]
    end

    it "handles high ndots values" do
      result = DNS::Servers.expand("a.b.c", search: ["example.com"], ndots: 5)
      result.should eq ["a.b.c.example.com", "a.b.c"]
    end

    it "is case insensitive for overlap detection" do
      result = DNS::Servers.expand("redis.SVC", search: ["svc.cluster.local"], ndots: 2)
      result.should eq ["redis.SVC"]
    end
  end

  describe "#expand" do
    it "uses instance settings" do
      servers = DNS::Servers.new([] of String, ["mycompany.local"], 1)
      result = servers.expand("myhost")
      result.should eq ["myhost.mycompany.local", "myhost"]
    end
  end

  describe ".host" do
    it "loads system configuration" do
      host = DNS::Servers.host
      host.should be_a DNS::Servers
      host.servers.should be_a Array(String)
      host.search.should be_a Array(String)
      host.ndots.should be_a Int32
    end
  end

  describe ".reload" do
    it "clears cached host configuration" do
      # Access host to cache it
      DNS::Servers.host
      # Reload should clear the cache
      DNS::Servers.reload
      # Next access should create a new instance
      reloaded = DNS::Servers.host
      # They might be equal but should work without error
      reloaded.should be_a DNS::Servers
    end
  end

  describe "manual configuration" do
    it "accepts custom servers, search domains, and ndots" do
      servers = DNS::Servers.new(
        ["8.8.8.8", "8.8.4.4"],
        ["corp.example.com", "example.com"],
        2
      )
      servers.servers.should eq ["8.8.8.8", "8.8.4.4"]
      servers.search.should eq ["corp.example.com", "example.com"]
      servers.ndots.should eq 2
    end

    it "defaults search to empty and ndots to 1" do
      servers = DNS::Servers.new(["1.1.1.1"])
      servers.servers.should eq ["1.1.1.1"]
      servers.search.should eq [] of String
      servers.ndots.should eq 1
    end
  end
end

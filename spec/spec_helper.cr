require "spec"
require "../src/dns"
require "../src/dns/resolver/https"
require "../src/dns/ext/addrinfo"

::Log.setup("*", :trace)

Spec.before_suite do
  ::Log.setup("*", :trace)
end

Spec.before_each do
  DNS.cache = DNS::Cache::HashMap.new
  DNS.default_resolver = DNS::Resolver::UDP.new
end

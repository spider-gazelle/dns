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

  # Network specs install their own local resolver.
  DNS.default_resolver = DNS::Resolver::UDP.new([] of String)
end

require "spec"
require "../src/dns"
require "../src/dns/resolver/https"

Spec.before_each do
  DNS.cache = DNS::Cache::HashMap.new
  DNS.default_resolver = DNS::Resolver::UDP.new
end

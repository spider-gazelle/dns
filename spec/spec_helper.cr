require "spec"
require "../src/dns"
require "../src/dns/resolver/https"
require "../src/dns/ext/addrinfo"

::Log.setup("*", :trace)

Spec.before_suite do
  ::Log.setup("*", :trace)
end

servers = DNS::Servers.from_host
servers = DNS::Servers.fallback if servers.empty?
puts "Default Servers: #{servers}"

Spec.before_each do
  DNS.cache = DNS::Cache::HashMap.new

  # use fallback server for better CI consistency
  DNS.default_resolver = DNS::Resolver::UDP.new(DNS::Servers.fallback)
end

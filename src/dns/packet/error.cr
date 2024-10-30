class DNS::Packet::Error < IO::Error
end

# The name server was unable to interpret the query.
class DNS::Packet::FormatError < DNS::Packet::Error
end

# The name server was unable to process this query due to a problem with the name server.
class DNS::Packet::ServerError < DNS::Packet::Error
end

# signifies that the domain name referenced in the query does not exist.
# Meaningful only for responses from an authoritative name server
class DNS::Packet::NameError < DNS::Packet::Error
end

# The name server does not support the requested kind of query.
class DNS::Packet::NotImplementedError < DNS::Packet::Error
end

# The name server refuses to perform the specified operation for policy reasons.
class DNS::Packet::RefusedError < DNS::Packet::Error
end

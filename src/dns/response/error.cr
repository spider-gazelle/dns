class DNS::Response::Error < Exception
end

# The name server was unable to interpret the query.
class DNS::Response::FormatError < DNS::Response::Error
end

# The name server was unable to process this query due to a problem with the name server.
class DNS::Response::ServerError < DNS::Response::Error
end

# signifies that the domain name referenced in the query does not exist.
# Meaningful only for responses from an authoritative name server
class DNS::Response::NameError < DNS::Response::Error
end

# The name server does not support the requested kind of query.
class DNS::Response::NotImplementedError < DNS::Response::Error
end

# The name server refuses to perform the specified operation for policy reasons.
class DNS::Response::RefusedError < DNS::Response::Error
end

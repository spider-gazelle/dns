# an interface for interacting with DNS servers
abstract class DNS::Resolver
  @servers : Array(String) = [] of String
  @servers_lock : Mutex = Mutex.new
  @failure_counts : Hash(String, Int32) = Hash(String, Int32).new(0)

  property failure_limit : Int32 = 3

  # perform the DNS query, fetching using request_id => record_type
  abstract def query(domain : String, dns_server : String, fetch : Hash(UInt16, UInt16), & : DNS::Packet ->)

  # returns the list of DNS servers and their current ordering
  def servers
    @servers_lock.synchronize { @servers.dup }
  end

  # returns the current failure counts for the servers
  def failure_counts
    @servers_lock.synchronize { @failure_counts.dup }
  end

  protected def reset_failure_count(server : String) : Nil
    @servers_lock.synchronize { @failure_counts[server] = 0 }
  end

  protected def increment_failure_count(server : String)
    Log.trace { "DNS timeout communicating with #{server}" }
    @servers_lock.synchronize { @failure_counts[server] += 1 }
  end

  protected def demote_server(index : Int32, servers : Array(String))
    server = servers.delete_at(index)
    servers << server
    Log.trace { "demoting DNS server: #{server}, DNS server ordering updated" }

    # duplicate outside of lock for efficiency
    # and also reset the failure count
    new_server_order = servers.dup
    @servers_lock.synchronize do
      @servers = new_server_order
      @failure_counts[server] = 0
    end
  end

  # yields the server to be used for DNS lookup
  def select_server(& : String ->)
    servers = self.servers.dup

    begin
      attempts = servers.size
      index = 0
      error = uninitialized IO::Error | DNS::Packet::ServerError

      loop do
        server = servers[index]

        begin
          yield server

          # Reset failure count on success
          reset_failure_count server
          break
        rescue ex : IO::TimeoutError
          error = ex

          if increment_failure_count(server) >= failure_limit
            # Move server to the end of the list after multiple timeouts
            demote_server(index, servers)

            # Reset index to start from the new first server
            index = 0
          else
            # Try the next server
            index = (index + 1) % servers.size
          end
        rescue ex : IO::Error | DNS::Packet::ServerError
          error = ex

          # Move server to the end of the list due to connection error
          demote_server(index, servers)

          # Reset index to start from the new first server
          index = 0
        end

        attempts -= 1
        raise error if attempts == 0
      end
    end
  end
end

require "./resolver/udp"
require "./resolver/tls"
require "./resolver/mdns"
require "./resolver/system"

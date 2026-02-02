describe DNS do
  it "should resolve hostnames using the ext methods" do
    client = TCPSocket.new("www.google.com", 80)
    client.close
  end

  it "should resolve ips using the ext methods" do
    channel = Channel(Nil).new(1)
    server = TCPServer.new("127.0.0.1", 1234)
    spawn do
      channel.send(nil)
      while server.accept?
      end
    end

    channel.receive
    client = TCPSocket.new("127.0.0.1", 1234)
    client.close
    server.close
    channel.close
  end
end

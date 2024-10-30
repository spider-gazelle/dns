{% if flag?(:windows) %}
  require "./servers/windows"
{% elsif flag?(:darwin) %}
  require "./servers/darwin"
{% else %}
  require "./servers/unix"
{% end %}

# system defined DNS servers
module DNS::Servers
  class_property fallback : Array(String) { ["1.1.1.1", "8.8.8.8"] }

  def self.reload
    @@from_host = nil
  end
end

# add support for DNS suffix's?

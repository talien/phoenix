Phoenix: the annoying graphical firewall for Linux
==================================================

Phoenix is a personal firewall for Linux. Users can fine grain the processes'
network access. Phoenix asks the user if a new process wants to reach the network
and remembers the user's choice whether to allow or deny access. IP addresses can
be grouped into zones easing the management of the access control.

Compiling:

Build dependencies on ubuntu: libnetfilter-queue-dev, libglib2.0-dev, build-essential, automake, python-gtk2

``` 
autoreconf -i 
./configure --prefix /usr
make
make install
```

Tests (make check and make func-test) should be run as root.

Usage:
 * Create a config file:

```
# sample config file
#zones
[zones]
  local = 10.0.0.0/8
  internet = 0.0.0.0/0

[rule]
  program = /usr/bin/ssh
  verdict = accept

# aliases for users
# root user's program will be asked on user user's GUI
[alias]
  root = user
```

 * Start the client as user: 

 ``` phxclient.py ```

 * Start the phoenix daemon as root:

 ``` sudo phoenixd -f phoenix.conf ```

WARNING! phoenixd erases the iptables filter table and sets up it's own rules. It is not supported to use it together with other firewall solutions!

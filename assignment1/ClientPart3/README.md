# Build
g++ -Wall -std=c++11 client.cpp -o client

# Run server (Terminal A)
./server port_number

# Run client (Terminal B)
./client 127.0.0.1 port_number

# Run tcpdump (Terminal C)
sudo tcpdump -AX -i lo0 'host 127.0.0.1 and port_number'

# then try for example:
#   ls
#   who
#   uname

# Functionality
Here the client reads a command from standart input, it will autmoatically prepend a SYS and then sends the command to the server.
After it is sent the client exits.






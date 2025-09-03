# Build
g++ -Wall -std=c++11 server.cpp -o server
g++ -Wall -std=c++11 client.cpp -o client

# Run server (Terminal A)
./server port_number

# Run client (Terminal B)
./client 127.0.0.1 port_number

# Run tcpdump (Terminal C)
sudo tcpdump -AX -i lo0 'host 127.0.0.1 and port_number'

# then try for example:
#   cmd> ls -sal
#   cmd> who
#   cmd> uname -a
#   cmd> exit

# Functionality
The server executes an SYS <command> it recieves using the /bin/sh. Then the server sends the output back to the cæient before closing the connection.
The client runs in a loop wich is like this: read command from stdin, connect to server, send SYS <command>, recieve and print output and then prompt again.
You cn type in exit or quit to close the client.



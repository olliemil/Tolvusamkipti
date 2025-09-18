#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

int main(int argc, char *argv[]) {
    // a) Check command-line arguments
    // ./scanner <IP address> <low port> <high port>

    // b) Parse arguments (IP, low port, high port)

    // c) Create UDP socket

    // d) Set socket timeout (so recvfrom does not block forever)

    // e) Loop over port range
        // e1) Build destination address (server IP + current port)
        // e2) Send a UDP datagram to this port
        // e3) Try to receive response (with timeout)
        // e4) If response received → print port as open

    // f) Close socket and exit program

    return 0;
}

// Simple server for TSAM-409 Assignment 1 (Part 4)
// Build: g++ -Wall -std=c++11 server.cpp -o server
// Run:   ./server 5000

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <iostream>
#include <sstream>

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#endif

#define BACKLOG 5

class Client {
public:
  int sock;
  std::string name;
  Client(int s) : sock(s) {}
  ~Client() {}
};

std::map<int, Client*> clients;

int open_socket(int portno)
{
  struct sockaddr_in sk_addr;
  int sock;
  int set = 1;

#ifndef SOCK_NONBLOCK
  if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    perror("Failed to open socket");
    return -1;
  }
  int flags = fcntl(sock, F_GETFL, 0);
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    perror("Failed to set O_NONBLOCK");
  }
#else
  if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) < 0) {
    perror("Failed to open socket");
    return -1;
  }
#endif

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0) {
    perror("Failed to set SO_REUSEADDR");
  }

  memset(&sk_addr, 0, sizeof(sk_addr));
  sk_addr.sin_family = AF_INET;
  sk_addr.sin_addr.s_addr = INADDR_ANY;
  sk_addr.sin_port = htons(portno);

  if (bind(sock, (struct sockaddr*)&sk_addr, sizeof(sk_addr)) < 0) {
    perror("Failed to bind to socket");
    return -1;
  }
  return sock;
}

void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{
  close(clientSocket);
  if (*maxfds == clientSocket) {
    *maxfds = 0;
    for (auto const &p : clients) {
      *maxfds = std::max(*maxfds, p.second->sock);
    }
  }
  FD_CLR(clientSocket, openSockets);
}

void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds, char *buffer)
{
  std::string line(buffer);
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();

  const std::string prefix = "SYS ";
  if (line.compare(0, prefix.size(), prefix) == 0 && line.size() > prefix.size())
  {
    std::string cmd = line.substr(prefix.size());
    std::cout << "Executing: " << cmd << std::endl;

    std::string shell = "/bin/sh -c \"" + cmd + "\"";
    FILE* pipe = popen(shell.c_str(), "r");
    if (!pipe) {
      const char* err = "ERROR: failed to execute command.\n";
      send(clientSocket, err, strlen(err), 0);
    } else {
      char outbuf[4096];
      size_t nread;
      while ((nread = fread(outbuf, 1, sizeof(outbuf), pipe)) > 0) {
        size_t off = 0;
        while (off < nread) {
          ssize_t s = send(clientSocket, outbuf + off, nread - off, 0);
          if (s <= 0) break;
          off += static_cast<size_t>(s);
        }
      }
      pclose(pipe);
    }

    // Close after one command per connection
    closeClient(clientSocket, openSockets, maxfds);
    std::cout << "Response sent, connection closed: " << clientSocket << std::endl;
  }
  else
  {
    std::cout << "Unknown or malformed command from client: " << line << std::endl;
    const char* err = "ERROR: expected 'SYS <command>'\n";
    send(clientSocket, err, strlen(err), 0);
  }
}

int main(int argc, char *argv[])
{
  if (argc != 2) {
    printf("Usage: server <port>\n");
    exit(0);
  }

  int listenSock = open_socket(atoi(argv[1]));
  if (listenSock < 0) exit(0);

  printf("Listening on port: %d\n", atoi(argv[1]));
  if (listen(listenSock, BACKLOG) < 0) {
    printf("Listen failed on port %s\n", argv[1]);
    exit(0);
  }

  fd_set openSockets, readSockets, exceptSockets;
  FD_ZERO(&openSockets);
  FD_ZERO(&readSockets);
  FD_ZERO(&exceptSockets);

  FD_SET(listenSock, &openSockets);
  int maxfds = listenSock;

  bool finished = false;
  struct sockaddr_in client;
  socklen_t clientLen = sizeof(client);
  char buffer[1025];

  while (!finished)
  {
    readSockets = exceptSockets = openSockets;
    memset(buffer, 0, sizeof(buffer));
    std::vector<int> toErase;

    int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);
    if (n < 0) {
      perror("select failed - closing down\n");
      break;
    }

    if (FD_ISSET(listenSock, &readSockets)) {
      clientLen = sizeof(client);
      int clientSock = accept(listenSock, (struct sockaddr*)&client, &clientLen);
      if (clientSock >= 0) {
        FD_SET(clientSock, &openSockets);
        maxfds = std::max(maxfds, clientSock);
        clients[clientSock] = new Client(clientSock);
        printf("Client connected on server\n");
      }
      n--;
    }

    if (n > 0) {
      for (auto const &pair : clients)
      {
        Client *c = pair.second;
        if (FD_ISSET(c->sock, &readSockets)) {
          n--;
          int r = recv(c->sock, buffer, sizeof(buffer)-1, MSG_DONTWAIT);
          if (r <= 0) {
            printf("Client closed connection: %d\n", c->sock);
            closeClient(c->sock, &openSockets, &maxfds);
            toErase.push_back(c->sock);
          } else {
            buffer[r] = '\0';
            std::cout << buffer << std::endl;
            clientCommand(c->sock, &openSockets, &maxfds, buffer);
            // If clientCommand closed it, schedule erase:
            if (!FD_ISSET(c->sock, &openSockets)) {
              toErase.push_back(c->sock);
            }
          }
        }
      }
      for (int s : toErase) {
        delete clients[s];
        clients.erase(s);
      }
    }

    if (n > 0) {
      std::cout << "ERROR: not all sockets handled (n == " << n << ")" << std::endl;
    }
  }
}

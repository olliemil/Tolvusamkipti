# Assignment 5 - Client/Server Protocol (A5_21)

Group: A5_21
Members: Oliver Emil Kjaran (oliver23), Sindri Rafn Bjarkason (sindrib23)
trace_client_server.pcapng is the Wireshark capture filtered at tcp.port == 4100, 
and we are showing the LISTSERVERS, SENDMSG, GETMSG TCP exchanges between client and server

## Build
```bash
make

## to run this server:
# connect to a known peer (e.g., ORACLE on port 5003):
./tsamgroup21 4021 130.208.246.98 5003
# normally
./tsamgroup21 4021


## to test the client:
./client 130.208.246.98 4021 LISTSERVERS
./client 130.208.246.98 4021 SENDMSG,A5_3,Hello!
./client 130.208.246.98 4021 GETMSG

## Logging
All activity is logged to server.log and includes connections, messages, keepalives, and forwarding events.

## Files

tsamgroup21.cpp – main server code

client.cpp – client utility

Makefile – build script

README – this file

chatty_bot.txt - chattybot extra points

edge_bot.txt - edgebot extrapoints

indirect_bot.txt - indirect bot extrapoints
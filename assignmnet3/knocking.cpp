// =====================================================
// knocking_port()
// -----------------------------------------------------
// Purpose: Implements the final "knock" step of the TSAM
//          assignment. This sends your group's results
//          (ID, signature, hidden ports, and phrase) to
//          the E.X.P.S.T.N. port on the server. If the
//          knock is valid, the server replies with the
//          final secret message.
// 
// Parameters:
//   ip                 -> The server IP (130.208.246.98).
//   port               -> The knocking port (E.X.P.S.T.N.).
//   group_id           -> 1-byte ID assigned by the server.
//   signature          -> 4-byte XOR signature from SECRET.
//   secret_hidden_port -> Hidden port obtained from SECRET.
//   evil_hidden_port   -> Hidden port obtained from EVIL.
//   secret_phrase      -> Phrase obtained from CHECKSUM.
// 
// Returns: true if a response was received, false otherwise.
// =====================================================
bool knocking_port(const string& ip, int port,
                   uint8_t group_id, uint32_t signature,
                   int secret_hidden_port, int evil_hidden_port,
                   const string& secret_phrase) {
    cout << "[DEBUG] knocking_port called for IP: " << ip
         << ", port: " << port << endl;

    // ---- 1. Create a UDP socket for communication ----
    // AF_INET   -> IPv4
    // SOCK_DGRAM -> UDP
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        return false;
    }

    // ---- 2. Fill in the destination server address ----
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;         // IPv4
    server_addr.sin_port = htons(port);       // convert to network byte order
    inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr);

    // ---- 3. Build the "knock" message ----
    // Format: group_id,signature,secret_port,evil_port,phrase
    // Example: "34,2262952386,4096,4072,well-done-checksum"
    string message = to_string((int)group_id) + "," +
                     to_string(signature) + "," +
                     to_string(secret_hidden_port) + "," +
                     to_string(evil_hidden_port) + "," +
                     secret_phrase;

    cout << "[DEBUG] Sending knock message: " << message << endl;

    // ---- 4. Send the knock to the E.X.P.S.T.N. port ----
    if (sendto(sock, message.c_str(), message.size(), 0,
               (sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Send failed");
        close(sock);
        return false;
    }

    // ---- 5. Prepare to receive a response ----
    char buffer[1024];             // response buffer
    sockaddr_in from_addr{};       // address of responder
    socklen_t from_len = sizeof(from_addr);

    // Set a 4 second timeout on recv
    timeval tv{};
    tv.tv_sec = 4;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // ---- 6. Wait for the server's reply ----
    int received = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                            (sockaddr*)&from_addr, &from_len);
    if (received > 0) {
        buffer[received] = '\0'; // null-terminate the C string
        cout << "Knock response: " << buffer << endl;
        close(sock);
        return true;
    } else {
        cerr << "No response from knocking port." << endl;
    }

    // ---- 7. Cleanup ----
    close(sock);
    return false;
}
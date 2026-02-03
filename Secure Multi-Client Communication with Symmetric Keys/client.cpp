#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <chrono>

using std::vector;
using std::map;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::cin;
using std::thread;
using std::this_thread::sleep_for;
using std::chrono::milliseconds;
using std::to_string;
using std::stod;

constexpr int PORTNO = 12000;
constexpr size_t BUFFER_SIZE = 4096;

class SecureClient {
private:
    int socket_fd;
    uint8_t client_id;
    ProtocolState state;
    string server_host;
    int server_port;
    bool skip_key_updates;

public:
    SecureClient(uint8_t id, const string& host, int port, const vector<byte>& master_key)
        : client_id(id), server_host(host), server_port(port), 
          state(master_key, id), socket_fd(-1), skip_key_updates(false) {}

    void set_skip_key_updates(bool skip) {
        skip_key_updates = skip;
        cout << "[Client " << (int)client_id << "] Key updates: " 
             << (skip ? "DISABLED ⚠️" : "ENABLED ✓") << endl;
    }

    bool connect_to_server() {
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            perror("Client Socket");
            return false;
        }

        struct sockaddr_in servaddr;
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(server_port);

        if (inet_pton(AF_INET, server_host.c_str(), &servaddr.sin_addr) <= 0) {
            perror("inet_pton");
            return false;
        }

        if (::connect(socket_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
            perror("Client Connect");
            return false;
        }

        // Send client ID
        if (send(socket_fd, (char*)&client_id, 1, 0) < 0) {
            perror("send client id");
            return false;
        }

        cout << "[Client " << (int)client_id << "] Connected to server" << endl;
        return true;
    }

    bool send_hello() {
        cout << "[Client " << (int)client_id << "] Sending CLIENT_HELLO" << endl;

        // Initial key debug removed for submission compliance

        vector<byte> msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_HELLO,
            client_id,
            state.round_number,
            (uint8_t)Direction::CLIENT_TO_SERVER,
            {0x01},  // Minimal payload
            state.c2s_enc_key,
            state.c2s_mac_key);

        if (send(socket_fd, (char*)msg.data(), msg.size(), 0) < 0) {
            perror("send");
            return false;
        }

        // Extract ciphertext from sent message for key evolution
        vector<byte> sent_ct, sent_iv;
        ProtocolMessage::extract_ciphertext_and_iv(msg, sent_ct, sent_iv);

        // Receive SERVER_CHALLENGE
        char buffer[BUFFER_SIZE];
        ssize_t n = recv(socket_fd, buffer, BUFFER_SIZE, 0);
        if (n <= 0) {
            cerr << "[Client " << (int)client_id << "] Failed to receive challenge" << endl;
            return false;
        }

        vector<byte> recv_msg(buffer, buffer + n);
        uint8_t opcode, direction;
        uint32_t round;
        vector<byte> plaintext;

        bool verified = ProtocolMessage::verify_and_decrypt(
            recv_msg, opcode, client_id, round, direction, plaintext,
            state.s2c_enc_key, state.s2c_mac_key);

        if (!verified || opcode != (uint8_t)Opcode::SERVER_CHALLENGE ||
            direction != (uint8_t)Direction::SERVER_TO_CLIENT) {
            cerr << "[Client " << (int)client_id << "] Challenge verification failed" << endl;
            return false;
        }

        cout << "[Client " << (int)client_id << "] Received SERVER_CHALLENGE" << endl;

        // Extract ciphertext from received challenge for key evolution
        vector<byte> recv_ct, recv_iv;
        ProtocolMessage::extract_ciphertext_and_iv(recv_msg, recv_ct, recv_iv);

        // Update keys using actual ciphertext and IV
        state.update_c2s_keys(sent_ct, sent_iv);
        state.update_s2c_keys(recv_ct, recv_iv);

        // Transition to ACTIVE state after completing handshake
        state.transition((uint8_t)Opcode::CLIENT_HELLO);

        return true;
    }

    bool send_data(double value) {
        cout << "[Client " << (int)client_id << "] Sending CLIENT_DATA with value " << value << endl;

        string value_str = to_string(value);
        vector<byte> plaintext(value_str.begin(), value_str.end());

        vector<byte> msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA,
            client_id,
            state.round_number,
            (uint8_t)Direction::CLIENT_TO_SERVER,
            plaintext,
            state.c2s_enc_key,
            state.c2s_mac_key);

        if (send(socket_fd, (char*)msg.data(), msg.size(), 0) < 0) {
            perror("send");
            return false;
        }

        // Extract ciphertext from sent message for key evolution
        vector<byte> sent_ct, sent_iv;
        ProtocolMessage::extract_ciphertext_and_iv(msg, sent_ct, sent_iv);

        // Receive SERVER_AGGR_RESPONSE
        char buffer[BUFFER_SIZE];


        ssize_t n = recv(socket_fd, buffer, BUFFER_SIZE, 0);
        if (n <= 0) {
            cerr << "[Client " << (int)client_id << "] Failed to receive aggregation response" << endl;
            return false;
        }

        vector<byte> recv_msg(buffer, buffer + n);
        uint8_t opcode, direction;
        uint32_t round;
        vector<byte> response;

        bool verified = ProtocolMessage::verify_and_decrypt(
            recv_msg, opcode, client_id, round, direction, response,
            state.s2c_enc_key, state.s2c_mac_key);

        if (!verified) {
            cerr << "[Client " << (int)client_id << "] Response verification failed" << endl;
            return false;
        }

        if (opcode == (uint8_t)Opcode::KEY_DESYNC_ERROR) {
            cerr << "[Client " << (int)client_id << "] SERVER detected desynchronization" << endl;
            state.terminate();
            return false;
        }

        if (opcode != (uint8_t)Opcode::SERVER_AGGR_RESPONSE) {
            cerr << "[Client " << (int)client_id << "] Unexpected opcode" << endl;
            return false;
        }

        cout << "[Client " << (int)client_id << "] Received response: " 
             << string(response.begin(), response.end()) << endl;

        // Extract ciphertext from received message for key evolution
        vector<byte> recv_ct, recv_iv;
        ProtocolMessage::extract_ciphertext_and_iv(recv_msg, recv_ct, recv_iv);

        // Update keys using actual ciphertext and IV
        if (skip_key_updates) {
            cout << "[Client " << (int)client_id << "] ⚠️  SKIPPING KEY UPDATES (malicious mode)" << endl;
            // Don't update keys - this will cause desynchronization on next message
        } else {
            state.update_c2s_keys(sent_ct, sent_iv);
            state.update_s2c_keys(recv_ct, recv_iv);
        }

        return true;
    }

    bool send_terminate() {
        cout << "[Client " << (int)client_id << "] Sending TERMINATE" << endl;

        vector<byte> msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::TERMINATE,
            client_id,
            state.round_number,
            (uint8_t)Direction::CLIENT_TO_SERVER,
            {0x00},
            state.c2s_enc_key,
            state.c2s_mac_key);

        send(socket_fd, (char*)msg.data(), msg.size(), 0);
        state.terminate();
        return true;
    }

    void disconnect() {
        if (socket_fd >= 0) {
            close(socket_fd);
            cout << "[Client " << (int)client_id << "] Disconnected" << endl;
        }
    }

    bool is_connected() const {
        return socket_fd >= 0 && state.is_active();
    }
};

int main() {
    cout << "=== Secure Client - Interactive Mode ===" << endl;
    cout << "Enter client ID (1-3): ";
    uint8_t id;
    int temp_id;
    cin >> temp_id;
    id = static_cast<uint8_t>(temp_id);

    if (id < 1 || id > 3) {
        cerr << "Invalid client ID. Must be 1-3." << endl;
        return 1;
    }

    // Use deterministic pre-provisioned master key shared with server
    vector<byte> master_key = provision_master_key(id);

    SecureClient client(id, "127.0.0.1", PORTNO, master_key);

    if (!client.connect_to_server()) {
        cerr << "Failed to connect" << endl;
        return 1;
    }

    if (!client.send_hello()) {
        cerr << "Failed to send hello" << endl;
        return 1;
    }

    cout << "\n=== Connection Established ===" << endl;
    cout << "Commands:" << endl;
    cout << "  - Enter a number to send data" << endl;
    cout << "  - Type 'skip' to toggle key update skipping (for testing)" << endl;
    cout << "  - Type 'quit' or 'exit' to disconnect" << endl;
    cout << "================================\n" << endl;

    string input;
    while (client.is_connected()) {
        cout << "Client[" << (int)id << "]> ";
        cin >> input;

        if (input == "quit" || input == "exit") {
            cout << "Disconnecting..." << endl;
            break;
        }

        if (input == "skip") {
            static bool skip_mode = false;
            skip_mode = !skip_mode;
            client.set_skip_key_updates(skip_mode);
            continue;
        }

        try {
            double value = stod(input);
            if (!client.send_data(value)) {
                cerr << "Failed to send data. Connection may be lost." << endl;
                break;
            }
        } catch (...) {
            cerr << "Invalid input. Please enter a number, 'skip', or 'quit'." << endl;
        }

        sleep_for(milliseconds(50));
    }

    if (client.is_connected()) {
        client.send_terminate();
    }

    client.disconnect();
    cout << "Session ended." << endl;
    return 0;
}
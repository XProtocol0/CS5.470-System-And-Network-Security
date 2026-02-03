#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <numeric>

using std::vector;
using std::map;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::thread;
using std::mutex;
using std::lock_guard;
using std::accumulate;
using std::to_string;
using std::stod;

constexpr int PORTNO = 12000;
constexpr size_t BUFFER_SIZE = 4096;

// Global state for all clients
map<uint8_t, ProtocolState> client_states;
// Aggregate data per round across all clients (key = round number)
map<uint32_t, vector<double>> round_data;  

mutex global_mutex;

// Master keys for each client 
map<uint8_t, vector<byte>> master_keys;

void initialize_master_keys() {
    // Deterministic pre-provisioning: both client and server derive the same key
    for (uint8_t i = 1; i <= 3; i++) {
        master_keys[i] = provision_master_key(i);
        cout << "[Server] Provisioned master key for client " << (int)i << endl;
    }
}

void serve_client(int socket, struct sockaddr_in *cliaddr, uint8_t client_id) {
    cout << "[Server] Serving client " << (int)client_id << " from " 
         << inet_ntoa(cliaddr->sin_addr) << ":" << ntohs(cliaddr->sin_port) << endl;

    {
        lock_guard<mutex> lock(global_mutex);
        if (master_keys.find(client_id) == master_keys.end()) {
            cerr << "[Server] Unknown client " << (int)client_id << endl;
            close(socket);
            return;
        }
        // Reset per-client protocol state on new connection
        client_states.erase(client_id);
        client_states.emplace(client_id, ProtocolState(master_keys[client_id], client_id));
        // Debug: print initial keys for this client
        print_hex("[Server] C2S_ENC_0", client_states.at(client_id).c2s_enc_key);
        print_hex("[Server] C2S_MAC_0", client_states.at(client_id).c2s_mac_key);
    }

    char buffer[BUFFER_SIZE];

    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t n = recv(socket, buffer, BUFFER_SIZE, 0);
        
        if (n <= 0) {
            cout << "[Server] Client " << (int)client_id << " disconnected" << endl;
            break;
        }

        vector<byte> message(buffer, buffer + n);
        
        {
            lock_guard<mutex> lock(global_mutex);
            
            if (client_states.find(client_id) == client_states.end()) {
                cerr << "[Server] No state for client " << (int)client_id << endl;
                break;
            }

            ProtocolState& state = client_states.at(client_id);

            // Verify and decrypt
            uint8_t opcode, direction;
            uint32_t round;
            vector<byte> plaintext;

            bool verified = ProtocolMessage::verify_and_decrypt(
                message, opcode, client_id, round, direction, plaintext,
                state.c2s_enc_key, state.c2s_mac_key);

            if (!verified) {
                cerr << "[Server] Verification failed for client " << (int)client_id << endl;
                state.terminate();
                close(socket);
                break;
            }

            // Validate direction
            if (direction != (uint8_t)Direction::CLIENT_TO_SERVER) {
                cerr << "[Server] Invalid direction from client " << (int)client_id << endl;
                state.terminate();
                close(socket);
                break;
            }

            // Check round number
            if (round != state.round_number) {
                cerr << "[Server] Round mismatch. Expected: " << state.round_number 
                     << ", Got: " << round << " from client " << (int)client_id << endl;
                
                // Send KEY_DESYNC_ERROR
                vector<byte> error_msg = ProtocolMessage::build_message(
                    (uint8_t)Opcode::KEY_DESYNC_ERROR,
                    client_id,
                    state.round_number,
                    (uint8_t)Direction::SERVER_TO_CLIENT,
                    {0},  // Empty payload
                    state.s2c_enc_key,
                    state.s2c_mac_key);
                
                send(socket, (char*)error_msg.data(), error_msg.size(), 0);
                state.terminate();
                close(socket);
                break;
            }

            // Check opcode validity
            if (!state.is_valid_opcode(opcode)) {
                cerr << "[Server] Invalid opcode " << (int)opcode << " for client " << (int)client_id << endl;
                state.terminate();
                close(socket);
                break;
            }

            cout << "[Server] Received opcode " << (int)opcode << " from client " << (int)client_id 
                 << " at round " << round << ", plaintext: " << string(plaintext.begin(), plaintext.end()) << endl;

            // Extract ciphertext and IV from received message
            vector<byte> received_ciphertext, received_iv;
            if (!ProtocolMessage::extract_ciphertext_and_iv(message, received_ciphertext, received_iv)) {
                cerr << "[Server] Failed to extract ciphertext from message" << endl;
                state.terminate();
                close(socket);
                break;
            }

            // Process message
            switch (opcode) {
                case (uint8_t)Opcode::CLIENT_HELLO: {
                    cout << "[Server] CLIENT_HELLO from client " << (int)client_id << endl;
                    state.transition(opcode);
                    
                    // Send SERVER_CHALLENGE
                    vector<byte> challenge = generate_random(32);
                    vector<byte> challenge_msg = ProtocolMessage::build_message(
                        (uint8_t)Opcode::SERVER_CHALLENGE,
                        client_id,
                        state.round_number,
                        (uint8_t)Direction::SERVER_TO_CLIENT,
                        challenge,
                        state.s2c_enc_key,
                        state.s2c_mac_key);
                    
                    send(socket, (char*)challenge_msg.data(), challenge_msg.size(), 0);
                    
                    // Extract ciphertext from challenge message for key evolution
                    vector<byte> challenge_ct, challenge_iv;
                    ProtocolMessage::extract_ciphertext_and_iv(challenge_msg, challenge_ct, challenge_iv);
                    
                    // Update keys using ciphertext and IV (as nonce)
                    state.update_s2c_keys(challenge_ct, challenge_iv);
                    state.update_c2s_keys(received_ciphertext, received_iv);
                    break;
                }

                case (uint8_t)Opcode::CLIENT_DATA: {
                    cout << "[Server] CLIENT_DATA from client " << (int)client_id << " at round " << round << endl;
                    
                    // Extract numeric data
                    double value = 0.0;
                    if (!plaintext.empty()) {
                        try {
                            value = stod(string(plaintext.begin(), plaintext.end()));
                            // Store data for THIS ROUND
                            round_data[round].push_back(value);
                            cout << "[Server] Stored value " << value << " from client " << (int)client_id 
                                 << " for round " << round << endl;
                        } catch (...) {
                            cerr << "[Server] Failed to parse numeric data from client " << (int)client_id << endl;
                        }
                    }
                    
                    // Calculate aggregation for THIS ROUND across ALL clients
                    double sum = 0.0;
                    int count = 0;
                    if (round_data.find(round) != round_data.end()) {
                        sum = accumulate(round_data[round].begin(), round_data[round].end(), 0.0);
                        count = round_data[round].size();
                    }
                    
                    cout << "[Server] Round " << round << " aggregate: SUM=" << sum 
                         << " from " << count << " client(s)" << endl;
                    
                    string agg_result = "ROUND=" + to_string(round) + ",SUM=" + to_string(sum) + ",COUNT=" + to_string(count);
                    vector<byte> agg_bytes(agg_result.begin(), agg_result.end());
                    vector<byte> agg_msg = ProtocolMessage::build_message(
                        (uint8_t)Opcode::SERVER_AGGR_RESPONSE,
                        client_id,
                        state.round_number,
                        (uint8_t)Direction::SERVER_TO_CLIENT,
                        agg_bytes,
                        state.s2c_enc_key,
                        state.s2c_mac_key);
                    
                    send(socket, (char*)agg_msg.data(), agg_msg.size(), 0);
                    
                    // Extract ciphertext from aggregation message for key evolution
                    vector<byte> agg_ct, agg_iv;
                    ProtocolMessage::extract_ciphertext_and_iv(agg_msg, agg_ct, agg_iv);
                    
                    // Update keys using actual ciphertext and IV
                    state.update_s2c_keys(agg_ct, agg_iv);
                    state.update_c2s_keys(received_ciphertext, received_iv);
                    break;
                }

                case (uint8_t)Opcode::TERMINATE: {
                    cout << "[Server] TERMINATE from client " << (int)client_id << endl;
                    state.terminate();
                    close(socket);
                    return;
                }

                default:
                    cerr << "[Server] Unknown opcode " << (int)opcode << endl;
                    state.terminate();
                    close(socket);
                    return;
            }
        }
    }

    close(socket);
}

int main() {
    initialize_master_keys();

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Server Socket");
        exit(1);
    }

    // Allow reuse of address
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORTNO);

    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Server Bind");
        exit(1);
    }

    if (listen(sock, 10) < 0) {
        perror("Server Listen");
        exit(1);
    }

    cout << "[Server] Listening on port " << PORTNO << endl;

    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);

    while (true) {
        int new_sock = accept(sock, (struct sockaddr *)&cliaddr, &len);
        
        if (new_sock < 0) {
            perror("accept");
            continue;
        }

        // Receive client ID first
        char id_buffer[1];
        if (recv(new_sock, id_buffer, 1, 0) <= 0) {
            close(new_sock);
            continue;
        }

        uint8_t client_id = (uint8_t)id_buffer[0];
        
        // Serve client in separate thread
        thread t(serve_client, new_sock, &cliaddr, client_id);
        t.detach();
    }

    close(sock);
    return 0;
}
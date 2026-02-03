#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <chrono>

using std::vector;
using std::string;
using std::cout;
using std::cerr;
using std::endl;
using std::thread;
using std::this_thread::sleep_for;
using std::chrono::milliseconds;
using std::chrono::seconds;

constexpr int PORTNO = 12000;
constexpr size_t BUFFER_SIZE = 4096;
constexpr const char* SERVER_HOST = "127.0.0.1";

// Helper function to connect to server
int connect_to_server(uint8_t client_id) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(PORTNO);

    if (inet_pton(AF_INET, SERVER_HOST, &servaddr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        perror("Connection failed - Make sure server is running!");
        close(sock);
        return -1;
    }

    // Send client ID
    if (send(sock, (char*)&client_id, 1, 0) < 0) {
        perror("Failed to send client ID");
        close(sock);
        return -1;
    }

    cout << "[ATTACK] Connected to server as client " << (int)client_id << "\n";
    return sock;
}

class AttackSimulator {
public:
    //ATTACK 1: REPLAY ATTACK  
    static void replay_attack() {
     

        uint8_t client_id = 1;
        vector<byte> master_key = provision_master_key(client_id);
        ProtocolState state(master_key, client_id);

        // Connect to server
        int sock = connect_to_server(client_id);
        if (sock < 0) {
            cerr << "Failed to connect to server. Make sure server is running!\n";
            return;
        }

        cout << "[ATTACK] Step 1: Send CLIENT_HELLO\n";
        vector<byte> hello_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_HELLO, client_id, 0, 0, {0x01},
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)hello_msg.data(), hello_msg.size(), 0);
        
        // Extract and update keys
        vector<byte> hello_ct, hello_iv;
        ProtocolMessage::extract_ciphertext_and_iv(hello_msg, hello_ct, hello_iv);

        // Receive SERVER_CHALLENGE
        char buffer[BUFFER_SIZE];
        ssize_t n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> challenge(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(challenge, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                cout << "[ATTACK] Received SERVER_CHALLENGE\n";
                
                vector<byte> ch_ct, ch_iv;
                ProtocolMessage::extract_ciphertext_and_iv(challenge, ch_ct, ch_iv);
                
                state.update_c2s_keys(hello_ct, hello_iv);
                state.update_s2c_keys(ch_ct, ch_iv);
                state.transition((uint8_t)Opcode::CLIENT_HELLO);
            }
        }

        cout << "\n[ATTACK] Step 2: Send CLIENT_DATA (Round 0)\n";
        string data = "10.0";
        vector<byte> plaintext(data.begin(), data.end());
        vector<byte> captured_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext,
            state.c2s_enc_key, state.c2s_mac_key);
        
        cout << "[ATTACK] >> CAPTURING THIS MESSAGE FOR REPLAY <<\n";
        send(sock, (char*)captured_msg.data(), captured_msg.size(), 0);
        
        // Receive response and update keys
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                cout << "[ATTACK] Received: " << string(pt.begin(), pt.end()) << "\n";
                
                vector<byte> msg_ct, msg_iv, resp_ct, resp_iv;
                ProtocolMessage::extract_ciphertext_and_iv(captured_msg, msg_ct, msg_iv);
                ProtocolMessage::extract_ciphertext_and_iv(resp, resp_ct, resp_iv);
                
                state.update_c2s_keys(msg_ct, msg_iv);
                state.update_s2c_keys(resp_ct, resp_iv);
            }
        }

        cout << "\n[ATTACK] Step 3: Send another valid message (Round 1)\n";
        string data2 = "20.0";
        vector<byte> plaintext2(data2.begin(), data2.end());
        vector<byte> msg2 = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext2,
            state.c2s_enc_key, state.c2s_mac_key);
        send(sock, (char*)msg2.data(), msg2.size(), 0);
        
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                cout << "[ATTACK] Received: " << string(pt.begin(), pt.end()) << "\n";
                
                vector<byte> m2_ct, m2_iv, r2_ct, r2_iv;
                ProtocolMessage::extract_ciphertext_and_iv(msg2, m2_ct, m2_iv);
                ProtocolMessage::extract_ciphertext_and_iv(resp, r2_ct, r2_iv);
                
                state.update_c2s_keys(m2_ct, m2_iv);
                state.update_s2c_keys(r2_ct, r2_iv);
            }
        }

        cout << "\n[ATTACK] Step 4: REPLAY captured message from Round 0\n";
        cout << "[ATTACK] Current server round: " << state.round_number << "\n";
        cout << "[ATTACK] Replayed message round: 0\n";
        cout << "[ATTACK] Sending replayed packet...\n";
        
        send(sock, (char*)captured_msg.data(), captured_msg.size(), 0);
        
        // Try to receive response
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            bool verified = ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                                state.s2c_enc_key, state.s2c_mac_key);
            
            if (!verified) {
                cout << "  Server response HMAC verification FAILED\n";
                cout << "  Replay attack DETECTED by server\n";
            } else if (op == (uint8_t)Opcode::KEY_DESYNC_ERROR) {
                cout << "  Server sent KEY_DESYNC_ERROR\n";
                cout << "  Replay attack DETECTED and session terminated\n";
            } else {
                cout << "⚠ Unexpected response from server\n";
            }
        } else {
            cout << "  Server closed connection (replay detected)\n";
        }

        close(sock);
        cout << "[ATTACK] Connection closed\n";
    }

    // ATTACK 2: HMAC TAMPERING 
    static void hmac_tampering_attack() {
     

        uint8_t client_id = 2;
        vector<byte> master_key = provision_master_key(client_id);
        ProtocolState state(master_key, client_id);

        int sock = connect_to_server(client_id);
        if (sock < 0) {
            cerr << "  Failed to connect to server\n";
            return;
        }

        cout << "[ATTACK] Step 1: Complete handshake\n";
        vector<byte> hello_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_HELLO, client_id, 0, 0, {0x01},
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)hello_msg.data(), hello_msg.size(), 0);
        
        vector<byte> hello_ct, hello_iv;
        ProtocolMessage::extract_ciphertext_and_iv(hello_msg, hello_ct, hello_iv);

        char buffer[BUFFER_SIZE];
        ssize_t n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> challenge(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(challenge, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                vector<byte> ch_ct, ch_iv;
                ProtocolMessage::extract_ciphertext_and_iv(challenge, ch_ct, ch_iv);
                
                state.update_c2s_keys(hello_ct, hello_iv);
                state.update_s2c_keys(ch_ct, ch_iv);
                state.transition((uint8_t)Opcode::CLIENT_HELLO);
                cout << "[ATTACK] Handshake complete\n";
            }
        }

        cout << "\n[ATTACK] Step 2: Create CLIENT_DATA message\n";
        string data = "100.0";
        vector<byte> plaintext(data.begin(), data.end());
        vector<byte> msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext,
            state.c2s_enc_key, state.c2s_mac_key);
        
        cout << "[ATTACK] Original message size: " << msg.size() << " bytes\n";

        cout << "\n[ATTACK] Step 3: TAMPER with ciphertext (flip bit at position 30)\n";
        if (msg.size() > 30) {
            cout << "[ATTACK] Original byte[30] = 0x" << std::hex << (int)msg[30] << std::dec << "\n";
            msg[30] ^= 0xFF;  // Flip all bits
            cout << "[ATTACK] Modified byte[30] = 0x" << std::hex << (int)msg[30] << std::dec << "\n";
        }

        cout << "\n[ATTACK] Step 4: Send tampered message to server\n";
        send(sock, (char*)msg.data(), msg.size(), 0);
        
        cout << "[ATTACK] Waiting for server response...\n";
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            cout << "  Server sent a response (unexpected)\n";
        } else if (n == 0) {
            cout << "  Server CLOSED connection (tampering detected)\n";
            cout << "  HMAC verification FAILED on server side\n";
            cout << "  Tampering attack successfully DETECTED\n";
        } else {
            cout << "  Connection error (server rejected tampered packet)\n";
        }

        close(sock);
        cout << "[ATTACK] Connection closed\n";
    }

    // /ATTACK 3: KEY DESYNCHRONIZATION 
    static void key_desync_attack() {


        uint8_t client_id = 3;
        vector<byte> master_key = provision_master_key(client_id);
        ProtocolState state(master_key, client_id);

        int sock = connect_to_server(client_id);
        if (sock < 0) {
            cerr << "  Failed to connect to server\n";
            return;
        }

        cout << "[ATTACK] Step 1: Complete handshake\n";
        vector<byte> hello_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_HELLO, client_id, 0, 0, {0x01},
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)hello_msg.data(), hello_msg.size(), 0);
        
        vector<byte> hello_ct, hello_iv;
        ProtocolMessage::extract_ciphertext_and_iv(hello_msg, hello_ct, hello_iv);

        char buffer[BUFFER_SIZE];
        ssize_t n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> challenge(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(challenge, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                vector<byte> ch_ct, ch_iv;
                ProtocolMessage::extract_ciphertext_and_iv(challenge, ch_ct, ch_iv);
                
                state.update_c2s_keys(hello_ct, hello_iv);
                state.update_s2c_keys(ch_ct, ch_iv);
                state.transition((uint8_t)Opcode::CLIENT_HELLO);
                cout << "[ATTACK] Handshake complete\n";
            }
        }

        cout << "\n[ATTACK] Step 2: Send first CLIENT_DATA (normal)\n";
        string data1 = "50.0";
        vector<byte> plaintext1(data1.begin(), data1.end());
        vector<byte> msg1 = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext1,
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)msg1.data(), msg1.size(), 0);
        
        vector<byte> msg1_ct, msg1_iv;
        ProtocolMessage::extract_ciphertext_and_iv(msg1, msg1_ct, msg1_iv);

        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                cout << "[ATTACK] Received: " << string(pt.begin(), pt.end()) << "\n";
                
                vector<byte> resp_ct, resp_iv;
                ProtocolMessage::extract_ciphertext_and_iv(resp, resp_ct, resp_iv);
                
                // Update keys normally
                state.update_c2s_keys(msg1_ct, msg1_iv);
                state.update_s2c_keys(resp_ct, resp_iv);
                cout << "[ATTACK] Keys updated normally (client now at round " << state.round_number << ")\n";
            }
        }

        cout << "\n[ATTACK] Step 3: Send CLIENT_DATA but SKIP key update\n";
        string data2 = "75.0";
        vector<byte> plaintext2(data2.begin(), data2.end());
        vector<byte> msg2 = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext2,
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)msg2.data(), msg2.size(), 0);

        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                cout << "[ATTACK] Received: " << string(pt.begin(), pt.end()) << "\n";
                
                // *** MALICIOUS: Skip key update here ***
                cout << "[ATTACK] SKIPPING KEY UPDATE (malicious behavior)\n";
                cout << "[ATTACK] Client keys remain at round " << state.round_number << "\n";
                cout << "[ATTACK] Server keys will advance to round " << (state.round_number + 1) << "\n";
                // DON'T call update_c2s_keys() or update_s2c_keys()
            }
        }

        cout << "\n[ATTACK] Step 4: Try to send another message (keys desynchronized)\n";
        string data3 = "100.0";
        vector<byte> plaintext3(data3.begin(), data3.end());
        
        // Client uses old keys (still at old round)
        cout << "[ATTACK] Client encrypting with OLD keys (round " << state.round_number << ")\n";
        vector<byte> msg3 = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext3,
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)msg3.data(), msg3.size(), 0);
        
        cout << "[ATTACK] Waiting for server response...\n";
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            // Server will use NEW keys, so verification will fail
            bool verified = ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                                state.s2c_enc_key, state.s2c_mac_key);
            
            if (!verified) {
                cout << "  HMAC verification FAILED (key desync detected)\n";
                cout << "  Server and client keys are OUT OF SYNC\n";
            } else if (op == (uint8_t)Opcode::KEY_DESYNC_ERROR) {
                cout << "  Server sent KEY_DESYNC_ERROR\n";
                cout << "  Key desynchronization DETECTED and session terminated\n";
            }
        } else {
            cout << "  Server closed connection (desync detected)\n";
        }

        close(sock);
        cout << "[ATTACK] Connection closed\n";
    }

    // ATTACK 4: MESSAGE REORDERING
    static void message_reordering_attack() {
       

        // We'll use client 1 but try to skip a round
        uint8_t client_id = 1;
        vector<byte> master_key = provision_master_key(client_id);
        ProtocolState state(master_key, client_id);

        int sock = connect_to_server(client_id);
        if (sock < 0) {
            cerr << "  Failed to connect to server\n";
            return;
        }

        cout << "[ATTACK] Step 1: Complete handshake\n";
        vector<byte> hello_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_HELLO, client_id, 0, 0, {0x01},
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)hello_msg.data(), hello_msg.size(), 0);
        
        vector<byte> hello_ct, hello_iv;
        ProtocolMessage::extract_ciphertext_and_iv(hello_msg, hello_ct, hello_iv);

        char buffer[BUFFER_SIZE];
        ssize_t n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> challenge(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(challenge, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                vector<byte> ch_ct, ch_iv;
                ProtocolMessage::extract_ciphertext_and_iv(challenge, ch_ct, ch_iv);
                
                state.update_c2s_keys(hello_ct, hello_iv);
                state.update_s2c_keys(ch_ct, ch_iv);
                state.transition((uint8_t)Opcode::CLIENT_HELLO);
                cout << "[ATTACK] Handshake complete (now at round " << state.round_number << ")\n";
            }
        }

        cout << "\n[ATTACK] Step 2: Build message for Round 0\n";
        string data0 = "100.0";
        vector<byte> plaintext0(data0.begin(), data0.end());
        vector<byte> msg_round0 = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, 0, 0, plaintext0,
            state.c2s_enc_key, state.c2s_mac_key);
        cout << "[ATTACK] Message for round 0 created\n";

        cout << "\n[ATTACK] Step 3: Try to send message with WRONG round number\n";
        cout << "[ATTACK] Server expects round " << state.round_number << "\n";
        cout << "[ATTACK] But we're sending round 0 (reordering/replay)\n";
        
        send(sock, (char*)msg_round0.data(), msg_round0.size(), 0);
        
        cout << "[ATTACK] Waiting for server response...\n";
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        if (n > 0) {
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            bool verified = ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                                state.s2c_enc_key, state.s2c_mac_key);
            
            if (!verified) {
                cout << "  HMAC verification FAILED (wrong round keys)\n";
                cout << "  Message reordering DETECTED\n";
            } else if (op == (uint8_t)Opcode::KEY_DESYNC_ERROR) {
                cout << "  Server sent KEY_DESYNC_ERROR\n";
                cout << "  Round number mismatch detected\n";
                cout << "  Message reordering DETECTED and prevented\n";
            }
        } else {
            cout << "  Server closed connection (reordering detected)\n";
        }

        close(sock);
        cout << "[ATTACK] Connection closed\n";
    }

    // ATTACK 5: REFLECTION ATTACK 
    static void reflection_attack() {
      

        uint8_t client_id = 2;
        vector<byte> master_key = provision_master_key(client_id);
        ProtocolState state(master_key, client_id);

        int sock = connect_to_server(client_id);
        if (sock < 0) {
            cerr << "  Failed to connect to server\n";
            return;
        }

        cout << "[ATTACK] Step 1: Complete handshake\n";
        vector<byte> hello_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_HELLO, client_id, 0, 0, {0x01},
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)hello_msg.data(), hello_msg.size(), 0);
        
        vector<byte> hello_ct, hello_iv;
        ProtocolMessage::extract_ciphertext_and_iv(hello_msg, hello_ct, hello_iv);

        char buffer[BUFFER_SIZE];
        ssize_t n = recv(sock, buffer, BUFFER_SIZE, 0);
        vector<byte> server_challenge;
        
        if (n > 0) {
            server_challenge.assign(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            if (ProtocolMessage::verify_and_decrypt(server_challenge, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                vector<byte> ch_ct, ch_iv;
                ProtocolMessage::extract_ciphertext_and_iv(server_challenge, ch_ct, ch_iv);
                
                state.update_c2s_keys(hello_ct, hello_iv);
                state.update_s2c_keys(ch_ct, ch_iv);
                state.transition((uint8_t)Opcode::CLIENT_HELLO);
                cout << "[ATTACK] Handshake complete\n";
            }
        }

        cout << "\n[ATTACK] Step 2: Send valid data message to get server response\n";
        string data = "150.0";
        vector<byte> plaintext(data.begin(), data.end());
        vector<byte> data_msg = ProtocolMessage::build_message(
            (uint8_t)Opcode::CLIENT_DATA, client_id, state.round_number, 0, plaintext,
            state.c2s_enc_key, state.c2s_mac_key);
        
        send(sock, (char*)data_msg.data(), data_msg.size(), 0);
        
        vector<byte> data_ct, data_iv;
        ProtocolMessage::extract_ciphertext_and_iv(data_msg, data_ct, data_iv);

        cout << "[ATTACK] Waiting for server ACK...\n";
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        vector<byte> server_ack;
        
        if (n > 0) {
            server_ack.assign(buffer, buffer + n);
            cout << "[ATTACK] Received server ACK (Direction=1, S2C keys)\n";
            
            // Update keys for next round
            state.update_c2s_keys(data_ct, data_iv);
            
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            if (ProtocolMessage::verify_and_decrypt(server_ack, op, client_id, rnd, dir, pt,
                                                    state.s2c_enc_key, state.s2c_mac_key)) {
                vector<byte> ack_ct, ack_iv;
                ProtocolMessage::extract_ciphertext_and_iv(server_ack, ack_ct, ack_iv);
                state.update_s2c_keys(ack_ct, ack_iv);
            }
        }

        cout << "\n[ATTACK] Step 3: REFLECT server's ACK message back to server\n";
        cout << "[ATTACK] This message has Direction=1 (server→client)\n";
        cout << "[ATTACK] And uses S2C keys, not C2S keys\n";
        cout << "[ATTACK] Server should reject due to wrong direction/keys\n\n";
        
        send(sock, (char*)server_ack.data(), server_ack.size(), 0);
        
        cout << "[ATTACK] Waiting for server response...\n";
        n = recv(sock, buffer, BUFFER_SIZE, 0);
        
        if (n > 0) {
            cout << "  Server responded (unexpected - likely error message)\n";
            vector<byte> resp(buffer, buffer + n);
            uint8_t op, dir;
            uint32_t rnd;
            vector<byte> pt;
            
            // Try to decrypt with current keys
            bool verified = ProtocolMessage::verify_and_decrypt(resp, op, client_id, rnd, dir, pt,
                                                                state.s2c_enc_key, state.s2c_mac_key);
            if (verified && op == (uint8_t)Opcode::KEY_DESYNC_ERROR) {
                cout << "  Server sent KEY_DESYNC_ERROR\n";
                cout << "  Reflection attack DETECTED\n";
            }
        } else if (n == 0) {
            cout << "  Server closed connection immediately\n";
            cout << "  Reflection attack DETECTED and PREVENTED\n";
        } else {
            cout << "  Server rejected message (HMAC failure expected)\n";
            cout << "  Reflection attack DETECTED and PREVENTED\n";
        }

        close(sock);
        cout << "[ATTACK] Connection closed\n";
    }

    

    // MENU 
    static void show_menu() {
        cout << "\nAvailable Attack Tests:\n";
        cout << "  [1] Replay Attack                     \n";
        cout << "  [2] HMAC Tampering Attack             \n";
        cout << "  [3] Key Desynchronization Attack      \n";
        cout << "  [4] Message Reordering Attack         \n";
        cout << "  [5] Reflection Attack                 \n";
        cout << "  [0] Exit\n";
        cout << "\nSelect option: ";
    }

    static void run_interactive() {
        int choice;
        bool running = true;

        while (running) {
            show_menu();
            std::cin >> choice;

            switch (choice) {
                case 1:
                    replay_attack();
                    cout << "\nPress Enter to continue...";
                    std::cin.ignore();
                    std::cin.get();
                    break;

                case 2:
                    hmac_tampering_attack();
                    cout << "\nPress Enter to continue...";
                    std::cin.ignore();
                    std::cin.get();
                    break;

                case 3:
                    key_desync_attack();
                    cout << "\nPress Enter to continue...";
                    std::cin.ignore();
                    std::cin.get();
                    break;

                case 4:
                    message_reordering_attack();
                    cout << "\nPress Enter to continue...";
                    std::cin.ignore();
                    std::cin.get();
                    break;

                case 5:
                    reflection_attack();
                    cout << "\nPress Enter to continue...";
                    std::cin.ignore();
                    std::cin.get();
                    break;

        
                case 0:
                    cout << "\nExiting \n";
                    running = false;
                    break;

                default:
                    cout << "\n[ERROR] Invalid choice. Please select 0-6.\n";
                    std::cin.clear();
                    std::cin.ignore(10000, '\n');
                    cout << "\nPress Enter to continue...";
                    std::cin.get();
                    break;
            }
        }
    }
};

int main() {
    

    AttackSimulator::run_interactive();
    return 0;
}

#ifndef PROTOCOL_FSM_H
#define PROTOCOL_FSM_H

#include <vector>
#include <cstdint>

typedef unsigned char byte;

// PROTOCOL CONSTANTS 

enum class Opcode : uint8_t {
    CLIENT_HELLO        = 10,
    SERVER_CHALLENGE    = 20,
    CLIENT_DATA         = 30,
    SERVER_AGGR_RESPONSE = 40,
    KEY_DESYNC_ERROR    = 50,
    TERMINATE           = 60
};

enum class Phase : uint8_t {
    INIT      = 0,
    ACTIVE    = 1,
    TERMINATED = 2
};

enum class Direction : uint8_t {
    CLIENT_TO_SERVER = 0,
    SERVER_TO_CLIENT = 1
};

//  PROTOCOL STATE 

class ProtocolState {
public:
    std::vector<byte> master_key;
    uint8_t client_id;
    uint32_t round_number;
    Phase phase;
    
    // Encryption keys
    std::vector<byte> c2s_enc_key;  // Client-to-Server encryption
    std::vector<byte> c2s_mac_key;  // Client-to-Server MAC
    std::vector<byte> s2c_enc_key;  // Server-to-Client encryption
    std::vector<byte> s2c_mac_key;  // Server-to-Client MAC

    ProtocolState(const std::vector<byte>& master_key, uint8_t client_id);

    // Key evolution
    void update_c2s_keys(const std::vector<byte>& ciphertext, const std::vector<byte>& nonce);
    void update_s2c_keys(const std::vector<byte>& aggregated_data, const std::vector<byte>& status_code);

    // State management
    bool is_valid_opcode(uint8_t opcode);
    void transition(uint8_t opcode);
    void terminate();

    bool is_active() const { return phase == Phase::ACTIVE; }
    bool is_terminated() const { return phase == Phase::TERMINATED; }
};

// MESSAGE FORMAT 

class ProtocolMessage {
public:
    static std::vector<byte> build_message(
        uint8_t opcode,
        uint8_t client_id,
        uint32_t round,
        uint8_t direction,
        const std::vector<byte>& plaintext,
        const std::vector<byte>& enc_key,
        const std::vector<byte>& mac_key);

    static bool verify_and_decrypt(
        const std::vector<byte>& message,
        uint8_t& opcode,
        uint8_t& client_id,
        uint32_t& round,
        uint8_t& direction,
        std::vector<byte>& plaintext,
        const std::vector<byte>& enc_key,
        const std::vector<byte>& mac_key);
    
    // Helper to extract ciphertext and IV from raw message (for key evolution)
    static bool extract_ciphertext_and_iv(
        const std::vector<byte>& message,
        std::vector<byte>& ciphertext,
        std::vector<byte>& iv);
};

// Deterministic pre-provisioning of master keys per client_id.
std::vector<byte> provision_master_key(uint8_t client_id);

#endif // PROTOCOL_FSM_H

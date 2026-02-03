#include "protocol_fsm.h"
#include "crypto_utils.h"
#include <cstring>
#include <iostream>
#include <string>

// PROTOCOL FSM 

ProtocolState::ProtocolState(const std::vector<byte>& master_key, uint8_t client_id)
    : master_key(master_key), client_id(client_id), round_number(0), phase(Phase::INIT)
{
    // Initialize keys from master key
    c2s_enc_key = derive_key(master_key, "C2S-ENC");
    c2s_mac_key = derive_key(master_key, "C2S-MAC");
    s2c_enc_key = derive_key(master_key, "S2C-ENC");
    s2c_mac_key = derive_key(master_key, "S2C-MAC");
}

void ProtocolState::update_c2s_keys(const std::vector<byte>& ciphertext, const std::vector<byte>& nonce)
{
    // C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
    std::vector<byte> enc_input = c2s_enc_key;
    enc_input.insert(enc_input.end(), ciphertext.begin(), ciphertext.end());
    std::vector<byte> new_enc_key = sha256_hash(enc_input);
    // Truncate to AES_KEY_SIZE (16 bytes for AES-128)
    c2s_enc_key = std::vector<byte>(new_enc_key.begin(), new_enc_key.begin() + AES_KEY_SIZE);

    // C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
    std::vector<byte> mac_input = c2s_mac_key;
    mac_input.insert(mac_input.end(), nonce.begin(), nonce.end());
    c2s_mac_key = sha256_hash(mac_input);
    // Keep full 32 bytes for HMAC key

    // Note: round_number is incremented in update_s2c_keys() after full exchange
}

void ProtocolState::update_s2c_keys(const std::vector<byte>& aggregated_data, const std::vector<byte>& status_code)
{
    // S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
    std::vector<byte> enc_input = s2c_enc_key;
    enc_input.insert(enc_input.end(), aggregated_data.begin(), aggregated_data.end());
    std::vector<byte> new_enc_key = sha256_hash(enc_input);
    // Truncate to AES_KEY_SIZE (16 bytes for AES-128)
    s2c_enc_key = std::vector<byte>(new_enc_key.begin(), new_enc_key.begin() + AES_KEY_SIZE);

    // S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
    std::vector<byte> mac_input = s2c_mac_key;
    mac_input.insert(mac_input.end(), status_code.begin(), status_code.end());
    s2c_mac_key = sha256_hash(mac_input);
    // Keep full 32 bytes for HMAC key

    round_number++;
}

bool ProtocolState::is_valid_opcode(uint8_t opcode)
{
    switch (phase) {
        case Phase::INIT:
            return opcode == (uint8_t)Opcode::CLIENT_HELLO;
        case Phase::ACTIVE:
            return opcode == (uint8_t)Opcode::CLIENT_DATA || 
                   opcode == (uint8_t)Opcode::SERVER_AGGR_RESPONSE ||
                   opcode == (uint8_t)Opcode::KEY_DESYNC_ERROR ||
                   opcode == (uint8_t)Opcode::TERMINATE;
        case Phase::TERMINATED:
            return false;
        default:
            return false;
    }
}

void ProtocolState::transition(uint8_t opcode)
{
    switch (phase) {
        case Phase::INIT:
            if (opcode == (uint8_t)Opcode::CLIENT_HELLO) {
                phase = Phase::ACTIVE;
            }
            break;
        case Phase::ACTIVE:
            if (opcode == (uint8_t)Opcode::TERMINATE || opcode == (uint8_t)Opcode::KEY_DESYNC_ERROR) {
                phase = Phase::TERMINATED;
            }
            break;
        case Phase::TERMINATED:
            // No transitions from terminated state
            break;
    }
}

void ProtocolState::terminate()
{
    phase = Phase::TERMINATED;
}

// MESSAGE BUILDER 

std::vector<byte> ProtocolMessage::build_message(
    uint8_t opcode,
    uint8_t client_id,
    uint32_t round,
    uint8_t direction,
    const std::vector<byte>& plaintext,
    const std::vector<byte>& enc_key,
    const std::vector<byte>& mac_key)
{
    std::vector<byte> message;

    // Generate IV
    std::vector<byte> iv = generate_random(AES_BLOCK_SIZE);

    // Pad plaintext
    std::vector<byte> padded = pkcs7_pad(plaintext);

    // Encrypt
    std::vector<byte> ciphertext = aes_encrypt_cbc(padded, enc_key, iv);

    // Build header
    message.push_back(opcode);
    message.push_back(client_id);
    // Round (4 bytes, big-endian)
    message.push_back((round >> 24) & 0xFF);
    message.push_back((round >> 16) & 0xFF);
    message.push_back((round >> 8) & 0xFF);
    message.push_back(round & 0xFF);
    message.push_back(direction);
    
    // Add IV
    message.insert(message.end(), iv.begin(), iv.end());

    // Add ciphertext
    message.insert(message.end(), ciphertext.begin(), ciphertext.end());

    // Compute HMAC over header + ciphertext (but not HMAC itself)
    std::vector<byte> mac_data(message.begin(), message.end());
    std::vector<byte> hmac = compute_hmac(mac_key, mac_data);

    // Add HMAC
    message.insert(message.end(), hmac.begin(), hmac.end());

    return message;
}

bool ProtocolMessage::verify_and_decrypt(
    const std::vector<byte>& message,
    uint8_t& opcode,
    uint8_t& client_id,
    uint32_t& round,
    uint8_t& direction,
    std::vector<byte>& plaintext,
    const std::vector<byte>& enc_key,
    const std::vector<byte>& mac_key)
{
    // Minimum message size: 1 (opcode) + 1 (client_id) + 4 (round) + 1 (direction) + 16 (IV) + 32 (HMAC)
    const size_t MIN_MSG_SIZE = 1 + 1 + 4 + 1 + 16 + 32;
    if (message.size() < MIN_MSG_SIZE) {
        std::cerr << "Message too short" << std::endl;
        return false;
    }

    // Extract header fields
    size_t pos = 0;
    opcode = message[pos++];
    client_id = message[pos++];
    round = ((uint32_t)message[pos] << 24) |
            ((uint32_t)message[pos+1] << 16) |
            ((uint32_t)message[pos+2] << 8) |
            (uint32_t)message[pos+3];
    pos += 4;
    direction = message[pos++];

    // Extract IV
    std::vector<byte> iv(message.begin() + pos, message.begin() + pos + AES_BLOCK_SIZE);
    pos += AES_BLOCK_SIZE;

    // Extract HMAC (last 32 bytes)
    std::vector<byte> received_hmac(message.end() - HMAC_SIZE, message.end());

    // Verify HMAC before decryption
    std::vector<byte> mac_data(message.begin(), message.end() - HMAC_SIZE);
    std::vector<byte> computed_hmac = compute_hmac(mac_key, mac_data);

    if (computed_hmac != received_hmac) {
        std::cerr << "HMAC verification failed" << std::endl;
        return false;
    }

    // Extract ciphertext
    std::vector<byte> ciphertext(message.begin() + pos, message.end() - HMAC_SIZE);

    // Decrypt
    std::vector<byte> padded_plaintext = aes_decrypt_cbc(ciphertext, enc_key, iv);

    // Remove padding
    try {
        plaintext = pkcs7_unpad(padded_plaintext);
    } catch (const std::exception& e) {
        std::cerr << "Padding verification failed: " << e.what() << std::endl;
        return false;
    }

    return true;
}

bool ProtocolMessage::extract_ciphertext_and_iv(
    const std::vector<byte>& message,
    std::vector<byte>& ciphertext,
    std::vector<byte>& iv)
{
    // Message format: | Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) | Ciphertext (variable) | HMAC (32) |
    const size_t MIN_MSG_SIZE = 1 + 1 + 4 + 1 + 16 + 32; // Without ciphertext
    if (message.size() < MIN_MSG_SIZE) {
        return false;
    }

    // Extract IV (starts at byte 7, length 16)
    size_t iv_pos = 7;
    iv = std::vector<byte>(message.begin() + iv_pos, message.begin() + iv_pos + AES_BLOCK_SIZE);

    // Extract ciphertext (starts after IV, ends before HMAC)
    size_t ct_start = iv_pos + AES_BLOCK_SIZE;
    size_t ct_end = message.size() - HMAC_SIZE;
    ciphertext = std::vector<byte>(message.begin() + ct_start, message.begin() + ct_end);

    return true;
}

// MASTER KEY PROVISIONING 
std::vector<byte> provision_master_key(uint8_t client_id)
{
    static const std::string seed = "SNS-Lab1-Shared-Seed-2026";
    std::vector<byte> seed_bytes(seed.begin(), seed.end());
    std::string label = std::string("MASTER-") + std::to_string(client_id);
    // Derive HMAC-based key and truncate to AES_KEY_SIZE (16 bytes)
    std::vector<byte> full = derive_key(seed_bytes, label);
    return std::vector<byte>(full.begin(), full.begin() + AES_KEY_SIZE);
}

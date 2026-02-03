#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <string>

typedef unsigned char byte;

// Constants
constexpr size_t AES_BLOCK_SIZE = 16;
constexpr size_t AES_KEY_SIZE   = 16;  // AES-128
constexpr size_t HMAC_KEY_SIZE  = 32;  // SHA256 output
constexpr size_t HMAC_SIZE      = 32;  // SHA256 output

// PKCS#7 Padding
std::vector<byte> pkcs7_pad(const std::vector<byte>& data);
std::vector<byte> pkcs7_unpad(const std::vector<byte>& data);

// AES-128-CBC (manual padding disabled)
std::vector<byte> aes_encrypt_cbc(
    const std::vector<byte>& plaintext,
    const std::vector<byte>& key,
    const std::vector<byte>& iv);

std::vector<byte> aes_decrypt_cbc(
    const std::vector<byte>& ciphertext,
    const std::vector<byte>& key,
    const std::vector<byte>& iv);

// HMAC-SHA256
std::vector<byte> compute_hmac(
    const std::vector<byte>& key,
    const std::vector<byte>& data);

// SHA-256 Hash (for key evolution)
std::vector<byte> sha256_hash(const std::vector<byte>& data);

// Key Derivation using HMAC-SHA256
std::vector<byte> derive_key(
    const std::vector<byte>& key,
    const std::string& label);

// Generate random bytes
std::vector<byte> generate_random(size_t length);

// Utility
void print_hex(const std::string& label, const std::vector<byte>& data);
std::string hex_to_string(const std::vector<byte>& data);

#endif // CRYPTO_UTILS_H

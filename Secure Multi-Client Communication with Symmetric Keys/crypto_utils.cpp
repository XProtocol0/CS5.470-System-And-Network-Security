#include "crypto_utils.h"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

// PKCS#7 PADDING 

std::vector<byte> pkcs7_pad(const std::vector<byte>& data)
{
    size_t pad_len = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    std::vector<byte> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<byte>(pad_len));
    return padded;
}

std::vector<byte> pkcs7_unpad(const std::vector<byte>& data)
{
    if (data.empty() || data.size() % AES_BLOCK_SIZE != 0)
        throw std::runtime_error("Invalid padded data length");

    byte pad_len = data.back();
    if (pad_len == 0 || pad_len > AES_BLOCK_SIZE)
        throw std::runtime_error("Invalid PKCS#7 padding");

    for (size_t i = data.size() - pad_len; i < data.size(); i++) {
        if (data[i] != pad_len)
            throw std::runtime_error("Invalid PKCS#7 padding");
    }

    return std::vector<byte>(data.begin(), data.end() - pad_len);
}

//  AES-128-CBC (RAW) 
// EVP_aes_128_cbc automatically uses first 16 B of the key passed
std::vector<byte> aes_encrypt_cbc(
    const std::vector<byte>& plaintext,
    const std::vector<byte>& key,
    const std::vector<byte>& iv)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data());

    // Disable OpenSSL padding (MANDATORY)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<byte> ciphertext(plaintext.size());
    int out_len = 0;

    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                      plaintext.data(), plaintext.size());

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<byte> aes_decrypt_cbc(
    const std::vector<byte>& ciphertext,
    const std::vector<byte>& key,
    const std::vector<byte>& iv)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data());

    //  Disable OpenSSL padding (MANDATORY)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    std::vector<byte> plaintext(ciphertext.size());
    int out_len = 0;

    EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                      ciphertext.data(), ciphertext.size());

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

// HMAC-SHA256 
std::vector<byte> compute_hmac(
    const std::vector<byte>& key,
    const std::vector<byte>& data)
{
    unsigned int len = EVP_MAX_MD_SIZE;
    std::vector<byte> mac(len);

    HMAC(EVP_sha256(),
         key.data(), key.size(),
         data.data(), data.size(),
         mac.data(), &len);

    mac.resize(len);
    return mac;
}

// SHA-256 HASH 
std::vector<byte> sha256_hash(const std::vector<byte>& data)
{
    std::vector<byte> hash(EVP_MD_size(EVP_sha256()));
    unsigned int len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &len);
    EVP_MD_CTX_free(ctx);

    hash.resize(len);
    return hash;
}

// KEY DERIVATION 
std::vector<byte> derive_key(
    const std::vector<byte>& key,
    const std::string& label)
{
    std::vector<byte> label_bytes(label.begin(), label.end());
    std::vector<byte> input = key;
    input.insert(input.end(), label_bytes.begin(), label_bytes.end());
    return compute_hmac(key, input);
}

// RANDOM GENERATION 
std::vector<byte> generate_random(size_t length)
{
    std::vector<byte> random(length);
    if (RAND_bytes(random.data(), length) != 1) {
        throw std::runtime_error("Random generation failed");
    }
    return random;
}

// UTIL 
void print_hex(const std::string& label, const std::vector<byte>& data)
{
    std::cout << label << " (" << data.size() << " bytes): ";
    for (byte b : data)
        printf("%02x", b);
    std::cout << std::endl;
}

std::string hex_to_string(const std::vector<byte>& data)
{
    std::string result;
    for (byte b : data) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        result += buf;
    }
    return result;
}



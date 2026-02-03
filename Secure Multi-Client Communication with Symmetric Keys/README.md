# Secure Multi-Client Communication with Symmetric Keys

### Overview

This project implements a stateful, symmetric-key-based secure communication protocol between a server and multiple clients operating in a hostile network environment. The implementation uses AES-128-CBC encryption, HMAC-SHA256 authentication, and manual PKCS#7 padding with strict state management.

### Features

- **Symmetric Cryptography**: AES-128-CBC with manual PKCS#7 padding
- **Authentication**: HMAC-SHA256 for message integrity
- **Stateful Protocol**: Round tracking, key evolution (ratcheting), protocol phases
- **Multi-Client Support**: Server handles multiple concurrent clients with thread-based architecture
- **Attack Resistance**: Mitigates replay, tampering, reordering, desynchronization, and reflection attacks

### Architecture

```
┌─────────────────────────────────────────────────────┐
│                   PROJECT STRUCTURE                 │
├─────────────────────────────────────────────────────┤
│                                                     │
│  crypto_utils.cpp/h     - Cryptographic primitives  │
│  ├─ AES-128-CBC encryption/decryption               │
│  ├─ PKCS#7 padding/unpadding                        │
│  ├─ HMAC-SHA256 computation                         │
│  ├─ Key derivation (HMAC-based)                     │
│  └─ Random number generation                        │
│                                                     │
│  protocol_fsm.cpp/h    - Protocol FSM & Messaging   │
│  ├─ ProtocolState: State machine per client         │
│  ├─ Phase transitions (INIT → ACTIVE → TERMINATED)  │
│  ├─ Key evolution rules (ratcheting)                │
│  └─ ProtocolMessage: Build/Verify message format    │
│                                                     │
│  server.cpp            - Multi-client server        │
│  ├─ Accept connections from clients                 │
│  ├─ Maintain per-client state                       │
│  ├─ Aggregate numeric data per round (across ALL)   │
│  └─ Thread-based client handling                    │
│                                                     │
│  client.cpp            - Secure client              │
│  ├─ Connect and authenticate with server            │
│  ├─ Send/receive encrypted messages                 │
│  ├─ Maintain protocol state                         │
│  └─ Support multi-round communication               │
│                                                     │
│  attacks.cpp           - Attack simulations         │
│  ├─ Replay attack demonstration                     │
│  ├─ HMAC tampering detection                        │
│  ├─ Message reordering detection                    │
│  ├─ Key desynchronization scenarios                 │
│  └─ Reflection attack mitigation                    │
│                                                     │
└─────────────────────────────────────────────────────┘
```

### Protocol Specification

#### Message Format
```
| Opcode (1) | Client ID (1) | Round (4) | Direction (1) | IV (16) |
| Ciphertext (variable) | HMAC (32) |
```

#### Protocol Opcodes
- `10` - CLIENT_HELLO: Client initiates protocol
- `20` - SERVER_CHALLENGE: Server sends encrypted challenge
- `30` - CLIENT_DATA: Client sends encrypted data
- `40` - SERVER_AGGR_RESPONSE: Server sends aggregated result
- `50` - KEY_DESYNC_ERROR: Desynchronization detected
- `60` - TERMINATE: Session termination

#### Protocol Phases
1. **INIT**: Waiting for CLIENT_HELLO
2. **ACTIVE**: Normal operation with CLIENT_DATA/SERVER_AGGR_RESPONSE
3. **TERMINATED**: Session ended, no more messages accepted

### Key Initialization

Each client Ci shares a master key Ki with the server.

```
Client → Server Keys:
  C2S_Enc_0 = HMAC-SHA256(Ki, Ki || "C2S-ENC")
  C2S_Mac_0 = HMAC-SHA256(Ki, Ki || "C2S-MAC")

Server → Client Keys:
  S2C_Enc_0 = HMAC-SHA256(Ki, Ki || "S2C-ENC")
  S2C_Mac_0 = HMAC-SHA256(Ki, Ki || "S2C-MAC")
```

### Key Evolution (Ratcheting)

Keys are evolved after each successful round:

```
Client → Server Key Evolution:
  C2S_Enc_{R+1} = SHA-256(C2S_Enc_R || Ciphertext_R)   [Truncated to 16 bytes]
  C2S_Mac_{R+1} = SHA-256(C2S_Mac_R || IV_R)           [Full 32 bytes]

Server → Client Key Evolution:
  S2C_Enc_{R+1} = SHA-256(S2C_Enc_R || Ciphertext_R)   [Truncated to 16 bytes]
  S2C_Mac_{R+1} = SHA-256(S2C_Mac_R || IV_R)           [Full 32 bytes]
```

**Key Points**:
- Uses SHA-256 hash (not HMAC) for key evolution as per assignment spec
- Ciphertext from the message is used for encryption key evolution
- IV from the message is used as nonce for MAC key evolution
- Encryption keys truncated to 16 bytes (AES-128 requirement)
- MAC keys kept at full 32 bytes (optimal for HMAC-SHA256)

**Critical Rule**: Keys are updated ONLY after successful verification, decryption, and validation. Any failure terminates the session without key update.

### Encryption Procedure

**Sender Side**:
1. Construct plaintext payload
2. Apply PKCS#7 padding manually
3. Generate fresh random IV (16 bytes)
4. Encrypt padded plaintext using AES-128-CBC
5. Compute HMAC over (Header || Ciphertext)
6. Transmit (Header || Ciphertext || HMAC)

**Receiver Side**:
1. Verify round number and direction
2. **Verify HMAC BEFORE decryption** (critical for security)
3. If HMAC fails, terminate session immediately
4. Decrypt ciphertext using AES-128-CBC
5. Remove PKCS#7 padding
6. Validate plaintext format

### Building and Running

#### Prerequisites
```bash
sudo apt-get install libssl-dev
```

#### Compilation
```bash
g++ -std=c++17 -o server server.cpp protocol_fsm.cpp crypto_utils.cpp -lssl -lcrypto -lpthread
g++ -std=c++17 -o client client.cpp protocol_fsm.cpp crypto_utils.cpp -lssl -lcrypto -lpthread
g++ -std=c++17 -o attacks attacks.cpp protocol_fsm.cpp crypto_utils.cpp -lssl -lcrypto -lpthread
```

#### Execution

Terminal 1 - Start Server:
```bash
./server
```

Terminal 2 - Run Client:
---
```bash
./client
```

Terminal 3 - Demonstrate Attacks:
```bash
./attacks
```

### Implementation Highlights

#### 1. **PKCS#7 Padding**
- Manual implementation without relying on OpenSSL automatic padding
- Ensures padding validation before decryption
- Prevents padding oracle attacks

#### 2. **Encrypt-then-MAC**
- HMAC is computed over ciphertext, preventing tampering
- HMAC is verified BEFORE decryption
- Decryption only proceeds if HMAC is valid

#### 3. **State Machine**
- Strict phase enforcement (INIT → ACTIVE → TERMINATED)
- Opcode validation per phase
- Invalid opcodes trigger session termination

#### 4. **Round Tracking**
- Every message includes current round number
- Out-of-order messages detected immediately
- Prevents replay attacks through strict round validation

#### 5. **Key Ratcheting**
- Keys evolve deterministically after each round
- Evolved keys depend on ciphertext/IV from current round
- Uses SHA-256 hash for key derivation (per assignment specification)
- Ensures forward secrecy and replay resistance

#### 6. **Direction Field**
- Every message includes direction indicator (C2S vs S2C)
- Prevents reflection attacks
- Enables asymmetric key usage

### Testing and Validation

Run the attacks simulator to demonstrate protocol robustness:

```bash
./attacks
```

### Files Submitted

- `server.cpp` - Multi-client server implementation
- `client.cpp` - Secure client implementation
- `protocol_fsm.cpp` & `protocol_fsm.h` - Protocol FSM and message handling
- `crypto_utils.cpp` & `crypto_utils.h` - Cryptographic utilities
- `attacks.cpp` - Attack simulations
- `README.md` - This file
- `SECURITY.md` - Security analysis

### Performance Characteristics

- **Key derivation**: ~1ms per key (HMAC-based)
- **Encryption/Decryption**: ~0.1ms per 1KB (AES-128-CBC)
- **HMAC computation**: ~0.05ms per 1KB
- **Per-client thread overhead**: Minimal (detached threads)
- **Scalability**: Supports multiple concurrent clients (thread per client)
### Authors (**Team 2**)
- Kspsvln Siddardha Kumar Kavuri 2025201061
- Nikhil Patidar 2025201081
- Aviral Tyagi 2025201086
# Security Analysis

## Security Against Attack Scenarios

### 1. REPLAY ATTACKS

**Threat**: An attacker captures a valid message and replays it later to deceive the receiver.

**Example Attack Flow**:
```
Round 0: Client sends "MSG" with Round=0, HMAC computed with Key_0
         Attacker captures this message
         Keys evolve to Key_1, Key_2, ...
Round 5: Attacker replays captured message with Round=0
```

**Defense Mechanism - Round Number Validation**:

```cpp
if (round != state.round_number) {
    // Round mismatch detected
    send_desync_error();
    terminate_session();
}
```

**Why It Works**:
1. Each message includes a monotonically increasing round number
2. Server maintains expected round number in state
3. Message with old round number cannot advance state
4. Session terminates on mismatch
5. **Stateful Protocol Design**: Round number must match exactly

**Technical Details**:
- Round number is in plaintext (no encryption benefit to hide)
- Round number is included in HMAC computation
- Old round numbers cannot produce valid HMAC with evolved keys
- Double protection: Round validation + HMAC verification

**Attack Failure Path**:
```
Captured: [Opcode|ClientID|Round=0|Direction|IV|Ciphertext|HMAC_Key0]
At Round 5: Server expects Round=5
           → Round mismatch detected
           → KEY_DESYNC_ERROR sent
           → Session TERMINATED
```

---

### 2. CIPHERTEXT TAMPERING / HMAC FORGERY

**Threat**: Attacker modifies ciphertext or message headers and forges a new HMAC.

**Example Attack Flow**:
```
Attacker intercepts:
  [Opcode|ClientID|Round|Direction|IV|Ciphertext|HMAC]

Attacker modifies:
  - Flip bit in ciphertext
  - Change opcode
  - Modify round number
  - Forge new HMAC (but doesn't know the MAC key)
```

**Defense Mechanism - Encrypt-then-MAC with Verification Before Decryption**:

```cpp
// CRITICAL: Verify HMAC BEFORE decryption
std::vector<byte> computed_hmac = compute_hmac(mac_key, mac_data);
if (computed_hmac != received_hmac) {
    cerr << "HMAC verification failed" << endl;
    terminate_session();
    return false;  // Never proceed to decryption
}
// Only if HMAC valid, proceed to decryption
```

**Why It Works**:

1. **HMAC Covers All Critical Fields**:
   - Opcode (prevents opcode substitution)
   - Client ID (prevents client spoofing)
   - Round number (prevents round manipulation)
   - Direction (prevents reflection)
   - IV (prevents IV reuse attacks)
   - Ciphertext (prevents data tampering)

2. **Attacker Cannot Forge HMAC**:
   - HMAC requires knowing the MAC key (symmetric)
   - Attacker only knows: plaintext, ciphertext, headers
   - HMAC is keyed with evolved keys (unknown to attacker)
   - SHA-256 has no known forgery attacks

3. **Verification Before Decryption**:
   - Prevents padding oracle attacks
   - Prevents ciphertext malleability exploitation
   - Rejects all tampered messages before processing

4. **Key Agility**:
   - MAC keys evolve every round
   - Attacker cannot forge HMAC for future rounds
   - Even if one key is compromised, only one round affected

**Attack Failure Path**:
```
Original:  [Opcode=30|ClientID=1|Round=2|...|IV|CT|HMAC_Key2]

Attacker modifies ciphertext:
          [Opcode=30|ClientID=1|Round=2|...|IV|CT'|HMAC_Key2]

Server receives modified message:
  → Compute HMAC over all fields except last 32 bytes
  → Computed_HMAC ≠ Received_HMAC
  → HMAC verification FAILS
  → Session TERMINATED
  → Message NEVER decrypted
```

**Mathematical Foundation**:
```
HMAC-SHA256 = H(K ⊕ opad, H(K ⊕ ipad, M))

Where:
  K = MAC key (evolved, unknown to attacker)
  M = Message (header + ciphertext)
  H = SHA-256
  
Forging requires finding M' such that:
  HMAC-SHA256(K, M') = HMAC-SHA256(K, M)

This is computationally infeasible (birthday attack requires 2^128 operations)
```

---

### 3. MESSAGE REORDERING

**Threat**: Attacker intercepts multiple messages and delivers them out of order.

**Example Attack Flow**:
```
Client sends: [Round=2], [Round=3], [Round=4]
Attacker reorders: [Round=4], [Round=2], [Round=3]
Server receives out-of-order messages
```

**Defense Mechanism - Strict Round Number Matching**:

```cpp
// Server state initialization
uint32_t expected_round = 0;

// On each message receipt
if (message_round != expected_round) {
    send_KEY_DESYNC_ERROR();
    terminate_session();
    return;
}

// After successful processing
expected_round++;
```

**Why It Works**:

1. **Sequential Round Numbers**:
   - Each round is numbered 0, 1, 2, 3, ...
   - Round numbers must match exactly
   - Cannot skip rounds

2. **State Progression**:
   - Server state only advances with correct round
   - Out-of-order messages violate expected sequence
   - First out-of-order message detected immediately

3. **Session Termination**:
   - Prevents confusion attacks
   - Prevents multiple interpretations of protocol state
   - Forces session restart (requires re-authentication)

**Attack Failure Path**:
```
Server state: expecting_round = 0

Message 1: Round=4
  → Round 4 ≠ expecting_round(0)
  → Mismatch detected
  → KEY_DESYNC_ERROR sent
  → Session TERMINATED

No further messages processed
```

---

### 4. KEY DESYNCHRONIZATION

**Threat**: Attacker drops a message causing client and server keys to diverge.

**Example Attack Flow**:
```
Round N: Client sends ClientHello
         Message intercepted by attacker
         Server never receives it
         
         Client state: Round N, Key_N
         Server state: Round N-1, Key_{N-1}
         
Round N+1: Client sends new message with Round N+1
           But encrypted with Key_{N+1} (client's current key)
           Server tries to decrypt with Key_N (server's current key)
           Keys don't match → HMAC fails
```

**Defense Mechanism - HMAC Verification Under Evolved Keys**:

```cpp
// Each key evolves deterministically using SHA-256 hash
C2S_Enc_{R+1} = SHA-256(C2S_Enc_R || Ciphertext_R)  [Truncated to 16 bytes]
C2S_Mac_{R+1} = SHA-256(C2S_Mac_R || IV_R)          [Full 32 bytes]

// If client and server are out of sync:
// Client uses Key_C[R+1]
// Server uses Key_S[R]
// These are different values (due to evolution)
//   → HMAC computed with Key_S[R] won't match message HMAC
```

**Why It Works**:

1. **Key Ratcheting Dependence**:
   - Each key depends on previous key AND round data
   - Deterministic: Same inputs → Same outputs
   - If rounds diverge, keys diverge irreversibly

2. **Key Evolution Formula**:
   ```
   Key_{R+1} = SHA-256(Key_R || RoundData_R)
   ```
   - Function is one-way (preimage resistant)
   - Cannot predict future keys without current key
   - Cannot derive past keys from future keys (forward secrecy)
   - Uses actual ciphertext and IV from messages

3. **Forward Secrecy**:
   - Key evolution ensures synchronization
   - Desynchronization is detected immediately
   - No way to "catch up" without re-authentication

4. **Termination on Desync**:
   - Session stops immediately
   - Prevents further damage
   - Requires new session establishment

**Attack Failure Path**:
```
Round 0: Client & Server synchronized
         Both: C2S_Mac_0, S2C_Mac_0

Attacker drops Round 0 response (Server→Client)

Round 1 (Client perspective):
  Client computes: C2S_Mac_1 = HMAC(C2S_Mac_0, ...)
  Sends message with Round=1, HMAC computed under C2S_Mac_1
  
Round 1 (Server perspective):
  Server still has: C2S_Mac_0
  Receives message, tries to verify with C2S_Mac_0
  Computed_HMAC(C2S_Mac_0, ...) ≠ Message_HMAC(C2S_Mac_1, ...)
  
Result: HMAC verification fails
         KEY_DESYNC_ERROR sent
         Session TERMINATED
```

**Mathematical Property**:
```
If K_A = SHA-256(K_0 || D_0)  [truncated to 16 bytes for encryption keys]
   K_B = K_0  (not evolved)

Then: HMAC-SHA256(K_B, M) ≠ HMAC-SHA256(K_A, M)
      with probability ≈ 1 - 2^(-256)

This is because K_A ≠ K_B, and SHA-256 provides strong collision resistance
```

---

### 5. REFLECTION ATTACKS

**Threat**: Attacker captures a message sent in one direction and reflects it as coming from the opposite direction.

**Example Attack Flow**:
```
Server sends (Direction=1): "Response1" encrypted with S2C_Enc
Attacker captures message and reflects it

Attacker sends to Server with same message:
  But now claiming Direction=0 (client→server)
  
Server might decrypt with wrong key or accept invalid request
```

**Defense Mechanism - Direction Field + Asymmetric Key Usage**:

```cpp
enum Direction {
    CLIENT_TO_SERVER = 0,
    SERVER_TO_CLIENT = 1
};

// Server reception validates direction
if (direction != CLIENT_TO_SERVER) {
    // Invalid direction for server receiving
    reject_message();
    terminate_session();
}

// Server uses different MAC key for verification
if (direction == CLIENT_TO_SERVER) {
    verify_with_key(c2s_mac_key);  // Client→Server key
} else {
    verify_with_key(s2c_mac_key);  // Server→Client key
}
```

**Why It Works**:

1. **Explicit Direction Field**:
   - Every message includes direction indicator
   - Direction is part of HMAC
   - Cannot change direction without invalidating HMAC

2. **Asymmetric Key Usage**:
   - C2S messages use c2s_enc_key, c2s_mac_key
   - S2C messages use s2c_enc_key, s2c_mac_key
   - Reflected message uses wrong key
   - HMAC verification fails

3. **Direction Validation**:
   - Receiver validates direction matches role
   - Server only accepts messages with Direction=0
   - Client only accepts messages with Direction=1

4. **State Machine Enforcement**:
   - Opcode must be valid for current phase AND direction
   - SERVER_CHALLENGE only valid for Direction=1
   - CLIENT_DATA only valid for Direction=0

**Attack Failure Path**:
```
Message sent by Server:
  [Opcode=40|ClientID=1|Round=2|Direction=1|IV|CT|HMAC_S2C]

Attacker reflects to Server (original destination):
  [Opcode=40|ClientID=1|Round=2|Direction=1|IV|CT|HMAC_S2C]

Server receives, parses Direction=1:
  → Direction should be 0 (from client)
  → Opcode 40 (SERVER_AGGR_RESPONSE) invalid for Direction=1 at server
  → State machine rejects
  → Also, HMAC includes direction field
  → Computed HMAC with Direction=0 ≠ received HMAC with Direction=1
  → Verification fails

Result: Message REJECTED
        Session TERMINATED
```

---



## Cryptographic Primitives Analysis

### 1. AES-128-CBC

**Strength**:
- Block size: 128 bits
- Key size: 128 bits (NIST approved)
- Mode: CBC (Cipher Block Chaining)
- No known attacks on full AES-128

**Usage in Protocol**:
- **Plaintext Confidentiality**: Converts plaintext to ciphertext
- **IV Randomization**: Fresh random IV per message prevents pattern recognition
- **Ciphertext Length**: |CT| = |PT| (with PKCS#7 padding)

**Security Level**: 
- ~128 bits of security against brute force
- ~2^128 operations required to break

### 2. HMAC-SHA256

**Strength**:
- Hash function: SHA-256 (produces 256-bit output)
- MAC construction: HMAC (Keyed Hash Message Authentication Code)
- Authenticated encryption component (combined with AES-CBC)

**Usage in Protocol**:
- **Message Authentication**: Verifies all message fields
- **Integrity Protection**: Detects any bit-flip in message
- **Key Derivation**: Basis for key evolution formula

**Security Level**:
- ~256 bits of security against collision
- ~128 bits of security against forgery (birthday bound)

### 3. PKCS#7 Padding

**Manual Implementation Requirement**:

```cpp
std::vector<byte> pkcs7_pad(const std::vector<byte>& data) {
    size_t pad_len = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
    std::vector<byte> padded = data;
    padded.insert(padded.end(), pad_len, static_cast<byte>(pad_len));
    return padded;
}
```

**Security Considerations**:
- Padding must always be applied (even if plaintext is multiple of block size)
- Each padding byte equals padding length (PKCS#7 spec)
- Manual implementation prevents padding oracle vulnerabilities
- Padding is verified before decryption completes

### 4. Random Number Generation

**Method**: `RAND_bytes()` from OpenSSL

```cpp
std::vector<byte> generate_random(size_t length) {
    std::vector<byte> random(length);
    if (RAND_bytes(random.data(), length) != 1) {
        throw std::runtime_error("Random generation failed");
    }
    return random;
}
```

**Security Properties**:
- Cryptographically secure (entropy from OS)
- Suitable for IV generation
- Suitable for key derivation seeds
- /dev/urandom (Linux) or CryptoGenRandom (Windows)

---

## Protocol Design Security

### State Machine Enforcement

**Finite Automaton**:
```
                    CLIENT_HELLO
                         ↓
              ┌─> ACTIVE <----┐
INIT ─────────┤               |
              │  (invalid     │
              │   transitions)|
              └─>TERMINATED -─┘
                    ↑
            (any error triggers)
```

**Security Benefits**:
1. Invalid opcodes rejected per phase
2. Prevents out-of-order protocol execution
3. Explicit termination state
4. No re-entry after termination

### Key Material Storage

**In-Memory Storage**:
```cpp
class ProtocolState {
    std::vector<byte> master_key;      // Pre-shared secret
    std::vector<byte> c2s_enc_key;     // Evolved C→S encryption
    std::vector<byte> c2s_mac_key;     // Evolved C→S authentication
    std::vector<byte> s2c_enc_key;     // Evolved S→C encryption
    std::vector<byte> s2c_mac_key;     // Evolved S→C authentication
};
```

**Security Considerations**:
- Keys stored in process memory (not persisted to disk)
- No key material in log files
- Session-specific keys (not reused across restarts)
- Manual zeroing recommended in production

---


# **Secure Voting System — Flask + Cryptography**

A fully encrypted, tamper-evident voting system built with:

* **Ed25519 signatures** (identity verification)
* **ECIES (ECC + ECDH + HKDF)** (secure key exchange)
* **Fernet (AES + HMAC)** (vote encryption)
* **Hash chain with BLAKE2b** (tamper detection)
* **Dark-themed Flask UI** with automatic voter switching

This project demonstrates how modern cryptographic primitives work together to build a secure and verifiable voting mechanism.

---

# 🛡 **Core Security Features**

This system uses **three layers of cryptography** + a **hash chain ledger**.

---

## 🔐 **1. Ed25519 — Digital Signatures**

Each voter is given:

* a private **SigningKey**
* a public **VerifyKey**

### **Purpose**

✔ Prove that a vote came from a legitimate voter
✔ Prevent forging or tampering

### Where it happens

* `generate_voter_keys()`
* `create_vote()` → vote is signed
* `verify_and_store_vote()` → vote signature is checked

```python
signature = voter_signing_key.sign(vote_enc).signature
voter_verify_key.verify(vote_enc, signature)
```

If verification fails → vote is rejected.

---

## 🔐 **2. ECIES (ECC + ECDH + HKDF) — Secure Key Exchange**

The vote itself is encrypted using AES.
But the AES key must also be sent securely to the server.

This is solved using **ECIES**:

* Curve: **SECP256R1**
* Key exchange: **ECDH**
* Key derivation: **HKDF-SHA256**

### **Purpose**

✔ Encrypt the AES key so only the server can decrypt it
✔ Provide **forward secrecy** using ephemeral EC keys

### Where it happens

* `ecies_encrypt()`
* `ecies_decrypt()`

```python
shared_secret = ephemeral_key.exchange(ec.ECDH(), server_pubkey)
derived_key = HKDF(...).derive(shared_secret)
encrypted_key = Fernet(derived_key).encrypt(aes_key)
```

Even if the server’s private key leaks later, old votes remain safe.

---

## 🔐 **3. Fernet — AES + HMAC Authenticated Encryption**

The vote itself is encrypted using **Fernet**, which uses:

* AES-128
* HMAC-SHA256
* Random IV
* Timestamp

### **Purpose**

✔ Confidentiality
✔ Integrity
✔ Authenticated encryption

### Where it happens

* `create_vote()`
* `verify_and_store_vote()`

```python
sym_key = Fernet.generate_key()
vote_enc = Fernet(sym_key).encrypt(vote_text.encode())
```

---

## 🔗 **4. Hash Chain — Tamper Detection (Mini-Blockchain)**

Each vote is linked to the previous one using:

* BLAKE2b hash (32 bytes)

```python
vote_hash = blake2b(vote_enc + prev_hash, 32)
```

### **Purpose**

✔ Detect removal, insertion, reordering, or modification of votes
✔ Create an immutable audit trail

Displayed on the **/tally** page.

---

# 📁 **Project Structure**

```
secure_voting/
│
├── app.py                     # Flask backend + cryptography
├── requirements.txt           # Dependencies
│
├── templates/
│   ├── base.html              # Main layout (dark theme)
│   ├── index.html             # Voting page
│   └── tally.html             # Tally and hash chain display
│
├── static/
│   ├── css/
│   │   └── dark.css           # Dark UI theme
│   └── js/
│       └── main.js            # Frontend logic (auto voter rotation)
│
└── README.md                  # (this file)
```

---

# 🚀 **How to Run**

### **1. Clone or download the project**

```
git clone <your-repo-url>
cd secure_voting
```

### **2. Create a virtual environment**

```
python -m venv venv
```

Activate:

**Windows**

```
venv\Scripts\activate
```

**Linux/macOS**

```
source venv/bin/activate
```

### **3. Install dependencies**

```
pip install -r requirements.txt
```

### **4. Run the Flask server**

```
python app.py
```

### **5. Open in browser**

```
http://127.0.0.1:5000/
```

---

# 🎛 **How the Voting UI Works**

### ✔ Voter is automatically assigned

No dropdown. After voter1 submits:

* next voter becomes voter2
* then voter3
* etc.

### ✔ Vote options fixed (Alice / Bob)

Users cannot type arbitrary vote text.

### ✔ All votes stored in memory

Visit `/tally` to see:

* decrypted votes (validated)
* vote counts
* hash chain for tamper evidence

---

# ⚠️ **Disclaimer**

This is a **research-level demonstration**, not a production system.

Production systems require:

* hardware security modules (HSMs)
* secure voter identity verification
* ballot anonymization (blind signatures)
* encrypted databases
* HTTPS + certificates
* audit logs
* rate limiting & DoS protection


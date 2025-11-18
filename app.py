from flask import Flask, render_template, request, redirect, url_for, jsonify
import os
import json
import hashlib
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Dict, Any, List

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption, load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# nacl (Ed25519)
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def generate_voter_keys():
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return signing_key, verify_key


def generate_server_ec_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_ec_public_key(pubkey):
    return pubkey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


def deserialize_ec_public_key(bytes_data):
    return load_pem_public_key(bytes_data)


def ecies_encrypt(aes_key: bytes, recipient_pubkey):
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_key.exchange(ec.ECDH(), recipient_pubkey)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies-exchange"
    ).derive(shared_secret)
    f = Fernet(urlsafe_b64encode(derived_key))
    encrypted_key = f.encrypt(aes_key)
    ephemeral_pub = ephemeral_key.public_key()
    return encrypted_key, serialize_ec_public_key(ephemeral_pub)


def ecies_decrypt(encrypted_aes_key: bytes, ephemeral_pub_bytes: bytes, server_private_key):
    ephemeral_pub = deserialize_ec_public_key(ephemeral_pub_bytes)
    shared_secret = server_private_key.exchange(ec.ECDH(), ephemeral_pub)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecies-exchange"
    ).derive(shared_secret)
    f = Fernet(urlsafe_b64encode(derived_key))
    aes_key = f.decrypt(encrypted_aes_key)
    return aes_key


def create_vote(vote_text: str, server_pubkey, voter_signing_key: SigningKey):
    sym_key = Fernet.generate_key()
    f = Fernet(sym_key)
    vote_enc = f.encrypt(vote_text.encode())
    encrypted_key, ephemeral_pub_bytes = ecies_encrypt(sym_key, server_pubkey)
    signature = voter_signing_key.sign(vote_enc).signature
    return {
        "vote_encrypted": urlsafe_b64encode(vote_enc).decode(),
        "key_encrypted": urlsafe_b64encode(encrypted_key).decode(),
        "ephemeral_pub": urlsafe_b64encode(ephemeral_pub_bytes).decode(),
        "signature": urlsafe_b64encode(signature).decode()
    }


def verify_and_store_vote(
    vote_packet: Dict[str, Any],
    voter_verify_key: VerifyKey,
    server_ec_private_key,
    prev_hash: str ):
    try:
        vote_enc = urlsafe_b64decode(vote_packet["vote_encrypted"])
        key_enc = urlsafe_b64decode(vote_packet["key_encrypted"])
        ephemeral_pub = urlsafe_b64decode(vote_packet["ephemeral_pub"])
        signature = urlsafe_b64decode(vote_packet["signature"])
        voter_verify_key.verify(vote_enc, signature)
        aes_key = ecies_decrypt(key_enc, ephemeral_pub, server_ec_private_key)
        f = Fernet(aes_key)
        vote_plain = f.decrypt(vote_enc).decode()
        prev_hash_bytes = prev_hash.encode()
        vote_hash = hashlib.blake2b(vote_enc + prev_hash_bytes, digest_size=32).hexdigest()
        return {
            "vote_plain": vote_plain,
            "vote_hash": vote_hash
        }
    except BadSignatureError:
        print("Signature verification failed!")
        return None
    except Exception as e:
        print(f"Vote processing failed: {e}")
        return None


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)

SERVER_PRIV, SERVER_PUB = generate_server_ec_keypair()

# For demo: create a small in-memory voter registry with keys
VOTER_DB = {}
for i in range(1, 6):
    sk, vk = generate_voter_keys()
    VOTER_DB[f"voter{i}"] = {"sign": sk, "verify": vk}

# Store received vote packets (in-memory)
RECEIVED_VOTES: List[Dict[str, Any]] = []

@app.route("/")
def index():
    # Show available demo voters to choose (so user can simulate)
    voters = list(VOTER_DB.keys())
    return render_template("index.html", voters=voters)

@app.route('/submit_vote', methods=['POST'])
def submit_vote():
    data = request.json
    voter_id = data.get('voter_id')
    vote_text = data.get('vote_text')
    if not voter_id or not vote_text:
        return jsonify({'status':'error','msg':'voter_id and vote_text required'}), 400
    voter = VOTER_DB.get(voter_id)
    if not voter:
        return jsonify({'status':'error','msg':'unknown voter'}), 404
    vote_packet = create_vote(vote_text, SERVER_PUB, voter['sign'])
    # store along with claimed voter id
    RECEIVED_VOTES.append({"voter_id": voter_id, "packet": vote_packet})
    return jsonify({'status':'ok', 'packet': vote_packet})

@app.route('/tally')
def tally():
    results = {}
    prev_hash = '0' * 64
    chain = []
    for item in RECEIVED_VOTES:
        voter_id = item['voter_id']
        packet = item['packet']
        verify_key = VOTER_DB[voter_id]['verify']
        out = verify_and_store_vote(packet, verify_key, SERVER_PRIV, prev_hash)
        if out:
            results[out['vote_plain']] = results.get(out['vote_plain'], 0) + 1
            prev_hash = out['vote_hash']
            chain.append({'vote': out['vote_plain'], 'hash': out['vote_hash'], 'voter': voter_id})
    return render_template('tally.html', results=results, chain=chain)

@app.route('/api/clear', methods=['POST'])
def clear_votes():
    RECEIVED_VOTES.clear()
    return jsonify({'status':'ok'})

if __name__ == '__main__':
    app.run(debug=True)

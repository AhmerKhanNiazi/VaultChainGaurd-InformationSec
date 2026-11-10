import os
import json
import struct
import hashlib
import base64
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms as std_algorithms
from cryptography.hazmat.primitives import padding as sym_padding

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as _TripleDES
except ImportError:
    _TripleDES = std_algorithms.TripleDES
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


VSEC_MAGIC = b"VSEC\x01\x00"


def generate_des_key() -> bytes:
    return os.urandom(8)


def des_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(8)
    padder = sym_padding.PKCS7(64).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(_TripleDES(key * 3), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def des_decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(_TripleDES(key * 3), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext


def generate_rsa_keypair() -> tuple:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_key(des_key: bytes, public_key) -> bytes:
    return public_key.encrypt(
        des_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def rsa_sign(data_hash: bytes, private_key) -> bytes:
    return private_key.sign(
        data_hash,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        utils_prehashed()
    )


def utils_prehashed():
    return asym_utils.Prehashed(hashes.SHA256())


def rsa_verify(data_hash: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            data_hash,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            utils_prehashed()
        )
        return True
    except InvalidSignature:
        return False


def serialize_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_private_key(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None, backend=default_backend())


def deserialize_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


def package_vsec(
    original_filename: str,
    file_data: bytes,
    private_key,
    public_key
) -> tuple[bytes, dict]:
    des_key = generate_des_key()
    iv, ciphertext = des_encrypt(file_data, des_key)
    file_hash = sha256_hash(file_data)
    encrypted_des_key = rsa_encrypt_key(des_key, public_key)
    signature = rsa_sign(file_hash, private_key)
    private_pem = serialize_private_key(private_key)
    public_pem = serialize_public_key(public_key)

    metadata = {
        "original_filename": original_filename,
        "timestamp": datetime.now().isoformat(),
        "file_hash_hex": file_hash.hex(),
        "iv_hex": iv.hex(),
        "encrypted_des_key_b64": base64.b64encode(encrypted_des_key).decode(),
        "signature_b64": base64.b64encode(signature).decode(),
        "private_key_pem": private_pem.decode(),
        "public_key_pem": public_pem.decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
    }

    metadata_bytes = json.dumps(metadata).encode("utf-8")
    metadata_len = struct.pack(">I", len(metadata_bytes))
    vsec_data = VSEC_MAGIC + metadata_len + metadata_bytes

    summary = {
        "original_filename": original_filename,
        "file_hash_hex": file_hash.hex(),
        "timestamp": metadata["timestamp"],
        "des_key_hex": des_key.hex(),
        "iv_hex": iv.hex(),
        "encrypted_des_key_len": len(encrypted_des_key),
        "ciphertext_len": len(ciphertext),
        "signature_len": len(signature),
    }
    return vsec_data, summary


def unpackage_vsec(vsec_data: bytes) -> tuple[bytes, dict, bool, bool]:
    if not vsec_data.startswith(VSEC_MAGIC):
        raise ValueError("Invalid .vsec file: bad magic bytes.")

    offset = len(VSEC_MAGIC)
    metadata_len = struct.unpack(">I", vsec_data[offset:offset + 4])[0]
    offset += 4
    metadata_bytes = vsec_data[offset:offset + metadata_len]
    metadata = json.loads(metadata_bytes.decode("utf-8"))

    stored_hash = bytes.fromhex(metadata["file_hash_hex"])
    iv = bytes.fromhex(metadata["iv_hex"])
    encrypted_des_key = base64.b64decode(metadata["encrypted_des_key_b64"])
    signature = base64.b64decode(metadata["signature_b64"])
    ciphertext = base64.b64decode(metadata["ciphertext_b64"])
    private_key = deserialize_private_key(metadata["private_key_pem"].encode())
    public_key = deserialize_public_key(metadata["public_key_pem"].encode())

    des_key = rsa_decrypt_key(encrypted_des_key, private_key)
    plaintext = des_decrypt(iv, ciphertext, des_key)

    computed_hash = sha256_hash(plaintext)
    hash_match = computed_hash == stored_hash
    sig_valid = rsa_verify(stored_hash, signature, public_key)

    return plaintext, metadata, hash_match, sig_valid


def tamper_vsec_file(vsec_path: str) -> int:
    with open(vsec_path, "rb") as f:
        vsec_data = f.read()

    if not vsec_data.startswith(VSEC_MAGIC):
        raise ValueError("Invalid .vsec file: bad magic bytes.")

    header_len = len(VSEC_MAGIC)
    metadata_len = struct.unpack(">I", vsec_data[header_len:header_len + 4])[0]
    metadata_bytes = vsec_data[header_len + 4: header_len + 4 + metadata_len]
    metadata = json.loads(metadata_bytes.decode("utf-8"))

    ciphertext_bytes = base64.b64decode(metadata["ciphertext_b64"])
    if len(ciphertext_bytes) == 0:
        raise ValueError("Ciphertext payload is empty; cannot tamper.")

    tamper_offset = os.urandom(1)[0] % len(ciphertext_bytes)
    ct_list = bytearray(ciphertext_bytes)
    ct_list[tamper_offset] ^= 0xFF
    metadata["ciphertext_b64"] = base64.b64encode(bytes(ct_list)).decode()

    new_metadata_bytes = json.dumps(metadata).encode("utf-8")
    new_metadata_len = struct.pack(">I", len(new_metadata_bytes))
    new_vsec = VSEC_MAGIC + new_metadata_len + new_metadata_bytes

    with open(vsec_path, "wb") as f:
        f.write(new_vsec)

    return tamper_offset

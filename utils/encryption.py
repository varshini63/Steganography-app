# utils/encryption.py

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# -----------------------
# RSA Key Loading
# -----------------------

# Load Private Key
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load Public Key
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

# -----------------------
# Encryption Functions
# -----------------------

def encrypt_text(text, method):
    """
    Encrypts the given text using the specified method.

    Args:
        text (str): The plaintext to encrypt.
        method (str): The encryption method ('AES', 'RSA').

    Returns:
        str: Base64-encoded encrypted data.
    """
    if method == 'AES':
        key = os.urandom(32)  # AES-256 requires a 32-byte key
        nonce = os.urandom(12)  # 12-byte nonce for GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
        tag = encryptor.tag
        # Combine key, nonce, tag, and ciphertext
        combined = key + nonce + tag + ciphertext
        return base64.b64encode(combined).decode()
    elif method == '3DES':
        raise NotImplementedError("3DES encryption is not implemented yet.")
    elif method == 'RSA':
        ciphertext = public_key.encrypt(
            text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    else:
        raise ValueError(f"Unsupported encryption method: {method}")

def decrypt_text(encrypted_text, method):
    """
    Decrypts the given encrypted text using the specified method.

    Args:
        encrypted_text (str): Base64-encoded encrypted data.
        method (str): The encryption method used ('AES', 'RSA').

    Returns:
        str: The decrypted plaintext.

    Raises:
        ValueError: If decryption fails or method is unsupported.
    """
    try:
        encrypted_data = base64.b64decode(encrypted_text)
    except base64.binascii.Error as e:
        raise ValueError("Invalid base64-encoded data.") from e

    if method == 'AES':
        try:
            key = encrypted_data[:32]
            nonce = encrypted_data[32:44]
            tag = encrypted_data[44:60]
            ciphertext = encrypted_data[60:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted_text.decode()
        except Exception as e:
            raise ValueError("AES decryption failed.") from e
    elif method == '3DES':
        raise NotImplementedError("3DES decryption is not implemented yet.")
    elif method == 'RSA':
        try:
            ciphertext = base64.b64decode(encrypted_text)
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        except Exception as e:
            raise ValueError("RSA decryption failed.") from e
    else:
        raise ValueError(f"Unsupported decryption method: {method}")

# -----------------------
# Digital Signature Functions
# -----------------------

def generate_signature(data):
    """
    Generates a digital signature for the given data using RSA PSS.

    Args:
        data (str): The data to sign.

    Returns:
        str: Base64-encoded signature.
    """
    signature = private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(data, signature):
    """
    Verifies the digital signature for the given data.

    Args:
        data (str): The original data.
        signature (str): Base64-encoded signature to verify.

    Returns:
        bool: True if verification succeeds, False otherwise.
    """
    try:
        public_key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

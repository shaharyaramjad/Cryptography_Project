from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
import json

file_received_from_alice = 'encrypted.txt'
decrypted_image_file = 'image.jpg'
bob_private_key_file = 'bob_private_key.pem'
alice_verifying_key_file = 'alice_verifying_key.crt'


# Open the input file for reading in text format
f = open(file_received_from_alice, 'r')
# Read in the file contents and save them in the local variable encrypted_data
encrypted_data = json.loads(f.read())
# Close the file
f.close()

# Decode the hex values in to bytes
iv = bytes.fromhex(encrypted_data['iv'])
encrypted_aes_key = bytes.fromhex(encrypted_data['encrypted_aes_key'])
ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
signature = bytes.fromhex(encrypted_data['signature'])

# Load Bob's private RSA key
f = open(bob_private_key_file, 'rb')
bob_private_key = load_pem_private_key(f.read(),password=b'bobsecret')
# Close the file
f.close()

# Decrypt the AES key using Bob's private key
aes_key = bob_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=SHA256()),
        algorithm=SHA256(),
        label=None
    )
)

# Decrypt the file content using AES
cipher = AES.new(aes_key, AES.MODE_CFB, iv)
decryptor_data = cipher.decrypt(ciphertext)

# Verify the signature using Alice's public EC key
f = open(alice_verifying_key_file, 'rb')
alice_cert = load_pem_x509_certificate(f.read())
alice_public_key = alice_cert.public_key()
# Close the file
f.close()

try:
    alice_public_key.verify(
        signature,
        ciphertext,
        ec.ECDSA(SHA256())
    )
    print("Signature verified successfully!")
except Exception as e:
    print(f"Signature verification failed: {e}")
    raise

# Save the decrypted image
f = open(decrypted_image_file, 'wb')
f.write(decryptor_data)
# Close the file
f.close()



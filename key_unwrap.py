from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


def aes_key_wrap_encrypt(key, plaintext):
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise ValueError("La taille de la clé doit être de 128, 192 ou 256 bits.")

    n = len(plaintext) // 8
    if n < 2:
        raise ValueError("La taille du texte en clair doit être d'au moins 16 octets.")

    r = n + 1
    a = [b'\xA6', b'\x59', b'\x67', b'\x76']

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Étape 1 : Initialisation
    for j in range(6):
        for i in range(n):
            b = (j * n) + (i + 1)
            ciphertext = encryptor.update(a[j] + plaintext[i * 8:(i + 1) * 8])
            a.append(ciphertext[:8])
            a[b] = ciphertext[8:]

    # Étape 2 : Boucles de mélange
    for j in range(6):
        for i in range(1, r + 1):
            b = (j * r) + i
            t = (r * j) + i
            ciphertext = encryptor.update(a[t] + a[b])
            a[b] = ciphertext[:8]
            a[t] = ciphertext[8:]

    # Étape 3 : Format de sortie
    wrapped_key = b''.join(a[1:])

    return wrapped_key


def aes_key_wrap_decrypt(key, wrapped_key):
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
        raise ValueError("La taille de la clé doit être de 128, 192 ou 256 bits.")

    if len(wrapped_key) % 8 != 0:
        raise ValueError("La taille de la clé enveloppée doit être un multiple de 8 octets.")

    n = (len(wrapped_key) // 8) - 1
    if n < 1:
        raise ValueError("La taille de la clé enveloppée doit être d'au moins 16 octets.")

    r = n + 1
    a = [None] + [wrapped_key[i * 8:(i + 1) * 8] for i in range(n)]

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Étape 4 : Format d'entrée
    for j in range(5, -1, -1):
        for i in range(r, 0, -1):
            b = (j * r) + i
            t = (r * (j + 1)) - i
            ciphertext = decryptor.update(a[t] + a[b])
            a[b] = ciphertext[:8]

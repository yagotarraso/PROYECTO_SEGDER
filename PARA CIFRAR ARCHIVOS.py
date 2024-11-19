import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
import secrets

# Configuración
KEY = b'Segder2024'
CONTENT_FOLDER = "C:/Users/adria/Documents/GTDM/SEGDER/PRY/CONTENIDOS"  # Carpeta de destino de contenidos cifrados
INPUT_FOLDER = "C:/Users/adria/Documents/GTDM/SEGDER/PRY/INPUT"  # Carpeta con los archivos originales

def generate_aes_key():
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(KEY), salt

def encrypt_file(filepath, output_folder):
    with open(filepath, 'rb') as file:
        data = file.read()
    
    # Genera clave y IV
    key, salt = generate_aes_key()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Relleno (padding)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Cifrado
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_data = b"ENC" + salt + iv + encrypted_data  # Añade el encabezado ENC

    # Guarda el archivo cifrado
    filename = os.path.basename(filepath)
    output_path = os.path.join(output_folder, filename)
    with open(output_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    print(f"Archivo cifrado guardado en: {output_path}")

def encrypt_all_files(input_folder, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    files = os.listdir(input_folder)
    for file in files:
        filepath = os.path.join(input_folder, file)
        if os.path.isfile(filepath):
            encrypt_file(filepath, output_folder)
        else:
            print(f"Saltando carpeta: {file}")

if __name__ == "__main__":
    print("Cifrando archivos de la carpeta INPUT...")
    encrypt_all_files(INPUT_FOLDER, CONTENT_FOLDER)
    print("Cifrado completo.")

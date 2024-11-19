import socket
import os
from cryptography.hazmat.primitives import serialization, hashes, padding  # Importa padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets

# Configuración del servidor
HOST = 'localhost'  # IP del servidor
PORT = 65432        # Puerto del servidor
BUFFER_SIZE = 1024  # Tamaño de buffer para transmisión de datos
KEY = b'mysecretpassword'  # Clave de cifrado simétrico (debe ser de 16 bytes para AES-128)
CONTENT_FOLDER = "C:/Users/adria/Documents/GTDM/SEGDER/PRY/CONTENIDOS"  # Carpeta donde se almacenan los contenidos

def generate_aes_key():
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(KEY), salt

def encrypt_file(data):
    key, salt = generate_aes_key()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Aplica relleno (padding) a los datos
    padder = padding.PKCS7(128).padder()  # 128 bits (16 bytes) de bloque para AES
    padded_data = padder.update(data) + padder.finalize()

    # Cifrar los datos con relleno
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return salt + iv + encrypted_data

def list_files():
    files = os.listdir(CONTENT_FOLDER)
    return '\n'.join(files).encode()

def send_file(filename, conn):
    filepath = os.path.join(CONTENT_FOLDER, filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as file:
            data = file.read()
            encrypted_data = encrypt_file(data)
            conn.sendall(encrypted_data)
            print(f"Archivo '{filename}' enviado correctamente.")
    else:
        conn.sendall(b"ERROR: Archivo no encontrado.")

def start_content_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Servidor de contenidos escuchando en {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            print(f"Conexión establecida con {addr}")
            request = conn.recv(BUFFER_SIZE).decode()

            if request == "LIST":
                conn.sendall(list_files())
            else:
                print(f"Archivo solicitado: {request}")
                send_file(request, conn)
            conn.close()

if __name__ == "__main__":
    start_content_server()

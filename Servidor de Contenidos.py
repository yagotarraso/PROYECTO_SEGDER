import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets

# Configuración del servidor
HOST = 'localhost'  # IP del servidor
PORT = 65432        # Puerto del servidor
BUFFER_SIZE = 1024  # Tamaño de buffer para transmisión de datos
KEY = b'mysecretpassword'  # Clave de cifrado simétrico (debe ser de 16 bytes para AES-128)

def generate_aes_key():
    # Deriva una clave de cifrado AES de la contraseña
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=algorithms.SHA256, length=16, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(KEY), salt

def encrypt_file(data):
    key, salt = generate_aes_key()
    iv = secrets.token_bytes(16)  # Genera un vector de inicialización para CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return salt + iv + encrypted_data  # Incluye la sal y el IV en el mensaje cifrado

def send_file(filename, conn):
    # Verifica si el archivo existe
    if os.path.exists(filename):
        with open(filename, 'rb') as file:
            data = file.read()
            encrypted_data = encrypt_file(data)
            conn.sendall(encrypted_data)  # Envía el archivo cifrado
            print(f"Archivo '{filename}' enviado correctamente.")
    else:
        conn.sendall(b"ERROR: Archivo no encontrado.")

# Inicia el servidor de contenidos
def start_content_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Servidor de contenidos escuchando en {HOST}:{PORT}...")
        
        while True:
            conn, addr = server_socket.accept()
            print(f"Conexión establecida con {addr}")
            filename = conn.recv(BUFFER_SIZE).decode()  # Recibe el nombre del archivo solicitado
            print(f"Archivo solicitado: {filename}")
            send_file(filename, conn)
            conn.close()

if __name__ == "__main__":
    start_content_server()

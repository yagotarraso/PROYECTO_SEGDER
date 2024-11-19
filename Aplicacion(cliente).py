import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Configuración del cliente
SERVER_HOST = 'localhost'  # IP del servidor
SERVER_PORT = 65432        # Puerto del servidor
BUFFER_SIZE = 1024         # Tamaño de buffer para transmisión de datos
KEY = b'mysecretpassword'  # Clave de cifrado simétrico (debe ser de 16 bytes para AES-128)

def derive_aes_key(salt):
    # Deriva la clave de cifrado AES usando la misma sal y clave que el servidor
    kdf = PBKDF2HMAC(algorithm=algorithms.SHA256, length=16, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(KEY)

def decrypt_file(encrypted_data):
    # Extrae la sal y el IV del archivo recibido
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = derive_aes_key(salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def request_file(filename):
    # Solicita un archivo al servidor de contenidos
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.sendall(filename.encode())  # Envía el nombre del archivo solicitado
        encrypted_data = client_socket.recv(BUFFER_SIZE)  # Recibe el archivo cifrado
        if b"ERROR" not in encrypted_data:
            decrypted_data = decrypt_file(encrypted_data)
            print(f"Contenido del archivo '{filename}':\n{decrypted_data.decode()}")
        else:
            print(encrypted_data.decode())

if __name__ == "__main__":
    filename = input("Ingrese el nombre del archivo que desea descargar: ")
    request_file(filename)

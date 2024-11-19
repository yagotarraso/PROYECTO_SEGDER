import socket 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding

# Configuración del cliente
SERVER_HOST = 'localhost'
SERVER_PORT = 65432
BUFFER_SIZE = 4096  # Aumentado para recibir datos grandes
KEY = b'mysecretpassword'

def derive_aes_key(salt):
    # Utiliza hashes.SHA256() en lugar de hashes.sha256
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(KEY)

def decrypt_file(encrypted_data):
    # Extrae la sal, IV y el texto cifrado
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    # Deriva la clave de AES
    key = derive_aes_key(salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Desencripta y elimina el relleno
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()  # Tamaño de bloque de 128 bits
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def request_file(filename):
    # Solicita un archivo al servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.sendall(filename.encode())
        
        # Recibe los datos cifrados del archivo
        encrypted_data = b""
        while True:
            packet = client_socket.recv(BUFFER_SIZE)
            if not packet:
                break
            encrypted_data += packet
        
        if b"ERROR" not in encrypted_data:
            decrypted_data = decrypt_file(encrypted_data)
            print(f"Contenido del archivo '{filename}':\n{decrypted_data.decode()}")
        else:
            print(encrypted_data.decode())

def list_files():
    # Solicita la lista de archivos disponibles en el servidor
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.sendall(b"LIST")
        files_list = client_socket.recv(BUFFER_SIZE).decode()
        print("Archivos disponibles en el servidor:\n", files_list)

if __name__ == "__main__":
    # Interfaz de usuario
    while True:
        print("\nOpciones:")
        print("1. Listar archivos")
        print("2. Descargar archivo")
        print("3. Salir")
        
        choice = input("Seleccione una opción: ")
        
        if choice == '1':
            list_files()
        elif choice == '2':
            filename = input("Ingrese el nombre del archivo que desea descargar: ")
            request_file(filename)
        elif choice == '3':
            break
        else:
            print("Opción no válida, intente nuevamente.")

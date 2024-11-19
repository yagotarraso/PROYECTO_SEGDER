import socket 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding

# Configuración del cliente
SERVER_HOST = 'localhost'
SERVER_PORT = 65432
BUFFER_SIZE = 4096
KEY = b'mysecretpassword'

def derive_aes_key(salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(KEY)

def decrypt_file(encrypted_data):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    key = derive_aes_key(salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def request_file(filename):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.sendall(filename.encode())
        
        # Recibe y procesa el encabezado de cifrado
        header = client_socket.recv(3)
        encrypted_data = b""
        
        if header == b"ENC":
            # Archivo cifrado, recibir el contenido completo
            while True:
                packet = client_socket.recv(BUFFER_SIZE)
                if not packet:
                    break
                encrypted_data += packet
            
            decrypted_data = decrypt_file(encrypted_data[3:])  # Omite "ENC" y descifra
            print(f"Contenido del archivo '{filename}':\n{decrypted_data.decode()}")
        
        elif header == b"PLAIN":
            # Archivo sin cifrar
            while True:
                packet = client_socket.recv(BUFFER_SIZE)
                if not packet:
                    break
                encrypted_data += packet
            print(f"Contenido del archivo '{filename}':\n{encrypted_data.decode()}")
        
        else:
            print("Error al recibir el archivo o archivo no encontrado.")

def list_files():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.sendall(b"LIST")
        files_list = client_socket.recv(BUFFER_SIZE).decode()
        print("Archivos disponibles en el servidor:\n", files_list)

if __name__ == "__main__":
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

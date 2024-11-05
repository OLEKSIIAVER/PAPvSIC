import os
import socket
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import CertificateSigningRequestBuilder, NameOID
import cryptography.x509 as x509
from datetime import datetime, timedelta

def generate_client_key_and_csr():
    # Генерація приватного ключа
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Генерація CSR
    client_csr = CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
    ])).sign(client_private_key, hashes.SHA256())

    # Збереження приватного ключа
    os.makedirs("client", exist_ok=True)
    with open("client/client_private.key", "wb") as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Збереження CSR
    with open("client/client_csr.pem", "wb") as f:
        f.write(client_csr.public_bytes(serialization.Encoding.PEM))

    return client_private_key, client_csr

def setup_ssl_context(private_key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile="client/client_certificate.pem", keyfile="client/client_private.key")
    context.load_verify_locations("ca/certs/ca_certificate.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def setup_client():
    # Генерація ключа та CSR
    private_key, client_csr = generate_client_key_and_csr()

    # Підключення до сервера для надсилання CSR
    with socket.create_connection(('localhost', 56789)) as client_socket:
        client_socket.sendall(client_csr.public_bytes(serialization.Encoding.PEM))
        print("CSR надіслано серверу.")

        # Отримання сертифіката від сервера
        server_cert = client_socket.recv(4096)
        if server_cert:
            with open("client/client_certificate.pem", "wb") as f:
                f.write(server_cert)
            print("Сертифікат клієнта отримано та збережено.")

    # Налаштування SSL-контексту з отриманим сертифікатом
    context = setup_ssl_context(private_key)

    # Підключення через захищений TLS
    with socket.create_connection(('localhost', 56789)) as client_socket:
        with context.wrap_socket(client_socket, server_hostname="localhost") as tls_client:
            print("Захищене з'єднання з сервером встановлено.")

if __name__ == "__main__":
    setup_client()

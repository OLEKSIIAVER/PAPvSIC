import os
import socket
import ssl
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import CertificateBuilder, NameOID, random_serial_number
import cryptography.x509 as x509

def create_ca_key():
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    os.makedirs("ca/private", exist_ok=True)
    with open("ca/private/ca_private.key", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return ca_private_key

def create_ca_certificate(private_key):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    ])

    cert = CertificateBuilder().subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(random_serial_number()) \
        .not_valid_before(datetime.now(timezone.utc)) \
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650)) \
        .sign(private_key, hashes.SHA256())

    os.makedirs("ca/certs", exist_ok=True)
    with open("ca/certs/ca_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Сертифікат CA створено та збережено.")

def setup_server():
    # Створення та налаштування SSL-контексту сервера
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="ca/certs/ca_certificate.pem", keyfile="ca/private/ca_private.key")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations("ca/certs/ca_certificate.pem")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 56789))
    server_socket.listen()

    print("Сервер запущено. Очікування з'єднань...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Підключено: {addr}")

        try:
            client_csr = conn.recv(4096)
            if client_csr:
                print("CSR отримано від клієнта.")
                conn.sendall(open("ca/certs/ca_certificate.pem", "rb").read())
            with context.wrap_socket(conn, server_side=True) as tls_conn:
                print("Захищене TLS-з'єднання встановлено.")
        except ssl.SSLError as e:
            print(f"Помилка SSL-з'єднання: {e}")

if __name__ == "__main__":
    setup_server()

import os
import ssl
import threading
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import TLS_FTPHandler
from pyftpdlib.servers import FTPServer
from ssl import SSLContext, PROTOCOL_TLS_SERVER, CERT_REQUIRED
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone, timedelta
import socket
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, END


# Генерация самоподписанного сертификата
def generate_certificates():
    try:
        # Генерация RSA-ключа
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Сохраняем приватный ключ
        with open("server.key", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Создаем Subject и Issuer (самоподписанный)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])

        # Генерируем сертификат
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=365)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256(), backend=default_backend())
        )

        # Сохраняем сертификат
        with open("server.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        # Обновляем отображение сертификата в интерфейсе
        with open("server.crt", "r") as f:
            app.cert_text.delete(1.0, END)
            app.cert_text.insert(END, f.read())

        messagebox.showinfo("Успех", "Сертификаты успешно сгенерированы!")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось сгенерировать сертификаты: {e}")


# Запуск FTP-сервера с поддержкой TLS
def start_ftp_server(ip="localhost", port=21, user="user", password="password"):
    try:
        authorizer = DummyAuthorizer()
        authorizer.add_user(user, password, homedir=".", perm="elradfmw")

        handler = TLS_FTPHandler
        handler.authorizer = authorizer

        # Настройки TLS
        handler.certfile = 'server.crt'
        handler.keyfile = 'server.key'
        handler.tls_control = True  # Шифрование команд
        handler.tls_data = True     # Шифрование данных

        server = FTPServer((ip, port), handler)
        ftp_thread = threading.Thread(target=server.serve_forever)
        ftp_thread.daemon = True
        ftp_thread.start()

        messagebox.showinfo("Успех", f"FTP-сервер запущен на {ip}:{port}")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось запустить FTP-сервер: {e}")


# Запуск TLS-сервера для обработки файлов
def start_tls_server(host, port):
    if not os.path.exists("server.crt") or not os.path.exists("server.key"):
        messagebox.showerror("Ошибка", "Сертификаты не найдены. Сгенерируйте их.")
        return

    def run_server():
        context = SSLContext(PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        context.verify_mode = CERT_REQUIRED  # Требовать клиентский сертификат
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
            sock.listen()
            print(f"TLS-сервер запущен на {host}:{port}")
            while True:
                conn, addr = sock.accept()
                print(f"Подключено клиентом: {addr}")
                try:
                    with context.wrap_socket(conn, server_side=True) as ssock:
                        data = ssock.recv(1024)
                        print(f"Полученные данные: {data[:50]}...")  # Показываем начало сообщения
                except Exception as e:
                    print(f"Ошибка при работе сервера: {e}")

    try:
        server_thread = threading.Thread(target=run_server)
        server_thread.daemon = True
        server_thread.start()
        messagebox.showinfo("Успех", f"TLS-сервер запущен на {host}:{port}")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось запустить TLS-сервер: {e}")


# Автоопределение IP и портов
def auto_detect_ports(ip_entry, tls_port_entry, ftp_port_entry):
    try:
        host = socket.gethostbyname(socket.gethostname())
        ip_entry.delete(0, END)
        ip_entry.insert(0, host)

        def is_port_free(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                return s.connect_ex((host, port)) != 0

        tls_port = 12345
        while not is_port_free(tls_port):
            tls_port += 1

        ftp_port = 21
        while not is_port_free(ftp_port):
            ftp_port += 1

        tls_port_entry.delete(0, END)
        tls_port_entry.insert(0, str(tls_port))
        ftp_port_entry.delete(0, END)
        ftp_port_entry.insert(0, str(ftp_port))

        messagebox.showinfo("Успех", "IP и порты успешно определены!")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось выполнить автоопределение: {e}")


# Интерфейс сервера
class ServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Сервер")
        self.root.geometry("900x700")
        self.root.configure(bg="#444")

        center_frame = tk.Frame(root, bg="#444")
        center_frame.pack(expand=True, padx=20, pady=20)

        # IP
        tk.Label(center_frame, text="IP-адрес сервера:", bg="#444", fg="white").grid(row=0, column=0, sticky="w")
        self.ip_entry = tk.Entry(center_frame, width=30)
        self.ip_entry.insert(0, "localhost")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)

        # TLS Port
        tk.Label(center_frame, text="Порт TLS:", bg="#444", fg="white").grid(row=1, column=0, sticky="w")
        self.tls_port_entry = tk.Entry(center_frame, width=30)
        self.tls_port_entry.insert(0, "12345")
        self.tls_port_entry.grid(row=1, column=1, padx=10, pady=5)

        # FTP Port
        tk.Label(center_frame, text="Порт FTP:", bg="#444", fg="white").grid(row=2, column=0, sticky="w")
        self.ftp_port_entry = tk.Entry(center_frame, width=30)
        self.ftp_port_entry.insert(0, "21")
        self.ftp_port_entry.grid(row=2, column=1, padx=10, pady=5)

        # Кнопки
        tk.Button(center_frame, text="Запустить сервер",
                  command=self.start_server_ui, bg="#555", fg="white").grid(
            row=3, column=0, columnspan=2, pady=10)
        tk.Button(center_frame, text="Автоопределение IP и портов",
                  command=lambda: auto_detect_ports(self.ip_entry, self.tls_port_entry, self.ftp_port_entry),
                  bg="#555", fg="white").grid(
            row=4, column=0, columnspan=2, pady=10)
        tk.Button(center_frame, text="Сгенерировать сертификаты",
                  command=generate_certificates, bg="#555", fg="white").grid(
            row=5, column=0, columnspan=2, pady=10)
        tk.Button(center_frame, text="Проверить соединение",
                  command=self.connect_to_server, bg="#555", fg="white").grid(
            row=6, column=0, columnspan=2, pady=10)

        # Сертификат
        tk.Label(center_frame, text="Сертификат сервера:", bg="#444", fg="white").grid(row=7, column=0, sticky="w")
        self.cert_text = scrolledtext.ScrolledText(center_frame, width=60, height=10, wrap=tk.WORD)
        self.cert_text.grid(row=8, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

    def start_server_ui(self):
        ip = self.ip_entry.get()
        tls_port = self.tls_port_entry.get()
        ftp_port = self.ftp_port_entry.get()

        if not ip or not tls_port.isdigit() or not ftp_port.isdigit():
            messagebox.showwarning("Ошибка", "Введите корректный IP и порты!")
            return

        start_tls_server(ip, int(tls_port))
        start_ftp_server(ip, int(ftp_port))

    def connect_to_server(self):
        ip = self.ip_entry.get()
        tls_port = self.tls_port_entry.get()

        if not ip or not tls_port.isdigit():
            messagebox.showwarning("Ошибка", "Введите IP-адрес сервера и порт TLS!")
            return

        try:
            with socket.create_connection((ip, int(tls_port)), timeout=2):
                pass
            messagebox.showinfo("Успех", "Подключение к серверу установлено!")
        except (socket.timeout, ConnectionRefusedError):
            messagebox.showerror("Ошибка", "Сервер недоступен.")


if __name__ == "__main__":
    root = tk.Tk()
    app = ServerApp(root)
    root.mainloop()
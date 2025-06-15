import os
import socket
from tkinter import filedialog, messagebox, scrolledtext, ttk, Tk, Frame, Label, Entry, Button, END, DoubleVar
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import ssl
import logging
from ftplib import FTP

# Настройки логирования
logging.basicConfig(level=logging.DEBUG)

# Загрузка публичного ключа
def load_public_key(file_path):
    try:
        with open(file_path, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Загруженный ключ не является RSA-публичным ключом.")
        return public_key
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл {file_path} не найден.")
    except Exception as e:
        raise ValueError(f"Ошибка при загрузке ключа: {e}")

# Загрузка приватного ключа
def load_private_key():
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        return private_key
    except FileNotFoundError:
        messagebox.showerror("Ошибка", "Приватный ключ не найден.")
        return None
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить приватный ключ: {e}")
        return None

# Генерация RSA-ключей
def generate_rsa_keys():
    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Сохраняем приватный ключ
        with open("private_key.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Сохранение публичного ключа
        with open("public_key.pem", "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи: {e}")
        return None

# Шифрование файла
def encrypt_file(file_path, aes_key, encrypted_key):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, "rb") as f:
            plaintext = f.read()

        # PKCS7 padding
        padding_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_len]) * padding_len

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Сохраняем: длина ключа → ключ → IV → шифротекст
        with open(file_path + ".enc", "wb") as f:
            f.write(len(encrypted_key).to_bytes(4, "big"))
            f.write(encrypted_key)
            f.write(iv)
            f.write(ciphertext)

        os.remove(file_path)
        return file_path + ".enc"
    except Exception as e:
        raise RuntimeError(f"Ошибка при шифровании: {e}")

# Расшифровка AES-ключа
def decrypt_aes_key(encrypted_key, private_key):
    try:
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return aes_key
    except Exception as e:
        raise ValueError(f"Не удалось расшифровать ключ: {e}")

# Расшифровка файла
def receive_and_decrypt_file(host, port, private_key):
    try:
        if not os.path.exists("server.crt"):
            messagebox.showerror("Ошибка", "Сертификат сервера не найден.")
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile="server.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True

        with socket.create_connection((host, int(port)), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Получение зашифрованного AES-ключа
                encrypted_aes_key_len = int.from_bytes(ssock.recv(4), "big")
                encrypted_aes_key = ssock.recv(encrypted_aes_key_len)
                # Получение IV
                iv = ssock.recv(16)
                # Получение шифротекста
                ciphertext = ssock.recv(4096)

        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        if aes_key is None:
            return None

        # Временно сохраняем полученный файл, чтобы получить корректный file_path
        temp_encrypted_path = "received_file.enc"
        with open(temp_encrypted_path, "wb") as f:
            f.write(iv + ciphertext)

        # Теперь передаем file_path в decrypt_file
        new_path = decrypt_file(temp_encrypted_path, iv, ciphertext, aes_key)
        os.remove(temp_encrypted_path)  # Удаляем временный .enc файл
        return new_path

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось получить или расшифровать файл: {e}")
        return None

# Отправка файла по TLS
def send_file(ip, port, file_path, public_key):
    try:
        if not os.path.exists("server.crt"):
            raise FileNotFoundError("Сертификат сервера не найден.")

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cafile="server.crt")
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        with socket.create_connection((ip, int(port))) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                logging.debug(f"SSL установлен: {ssock.cipher()}")

                # Отправляем длину ключа
                ssock.sendall(len(encrypted_key).to_bytes(4, "big"))
                ssock.sendall(encrypted_key)

                # Отправляем IV
                with open(file_path, "rb") as f:
                    data = f.read()
                ssock.sendall(data)

        messagebox.showinfo("Успех", "Файл успешно отправлен!")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось отправить файл: {e}")

# Скачивание сертификата через FTP
def download_certificate_via_ftp(server_ip):
    try:
        ftp = FTP()
        ftp.connect(server_ip, 21)
        ftp.login("user", "password")
        with open("server.crt", "wb") as f:
            ftp.retrbinary("RETR server.crt", f.write)
        ftp.quit()
        return True
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось скачать сертификат: {e}")
        return False

# Проверка соединения
def check_server_connection(ip, port):
    try:
        with socket.create_connection((ip, int(port)), timeout=2):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

# Интерфейс клиента
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Клиент")
        self.root.geometry("800x600")
        self.root.configure(bg="#444")

        center_frame = Frame(root, bg="#444")
        center_frame.pack(expand=True, padx=20, pady=20)

        Label(center_frame, text="Введите IP-адрес сервера:", bg="#444", fg="white").grid(row=0, column=0, sticky="w")
        self.ip_entry = Entry(center_frame, width=30, fg="gray")
        self.ip_entry.insert(0, "Введите IP-адрес сервера")
        self.ip_entry.bind("<FocusIn>", self.clear_ip_placeholder)
        self.ip_entry.bind("<FocusOut>", self.add_ip_placeholder)
        self.ip_entry.grid(row=0, column=0, pady=5, padx=10, sticky="w")

        Label(center_frame, text="Введите порт сервера:", bg="#444", fg="white").grid(row=1, column=0, sticky="w")
        self.port_entry = Entry(center_frame, width=30, fg="gray")
        self.port_entry.insert(0, "Введите порт сервера")
        self.port_entry.bind("<FocusIn>", self.clear_port_placeholder)
        self.port_entry.bind("<FocusOut>", self.add_port_placeholder)
        self.port_entry.grid(row=1, column=0, pady=5, padx=10, sticky="w")

        Button(center_frame, text="Получить сертификат", command=self.download_certificate, bg="#555", fg="white").grid(row=2, column=0, pady=10)
        Button(center_frame, text="Подключиться к серверу", command=self.connect_to_server, bg="#555", fg="white").grid(row=3, column=0, pady=10)

        buttons_left = [
            ("Сгенерировать ключи", self.generate_keys),
            ("Печать файла", self.print_file),
        ]
        buttons_right = [
            ("Получить файл от сервера", self.receive_and_decrypt),
        ]

        for i, (text, command) in enumerate(buttons_left):
            Button(center_frame, text=text, command=command, bg="#555", fg="white").grid(
                row=4, column=i, padx=5, pady=5, sticky="ew"
            )

        for i, (text, command) in enumerate(buttons_right):
            Button(center_frame, text=text, command=command, bg="#555", fg="white").grid(
                row=5, column=i, padx=5, pady=5, sticky="ew"
            )

        self.file_path = None
        self.decrypted_file_path = None

    def clear_ip_placeholder(self, event):
        if self.ip_entry.get() == "Введите IP-адрес сервера":
            self.ip_entry.delete(0, END)
            self.ip_entry.config(fg="black")

    def add_ip_placeholder(self, event):
        if self.ip_entry.get() == "":
            self.ip_entry.insert(0, "Введите IP-адрес сервера")
            self.ip_entry.config(fg="gray")

    def clear_port_placeholder(self, event):
        if self.port_entry.get() == "Введите порт сервера":
            self.port_entry.delete(0, END)
            self.port_entry.config(fg="black")

    def add_port_placeholder(self, event):
        if self.port_entry.get() == "":
            self.port_entry.insert(0, "Введите порт сервера")
            self.port_entry.config(fg="gray")

    def connect_to_server(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not ip or not port:
            messagebox.showwarning("Ошибка", "Заполните все поля!")
            return
        if check_server_connection(ip, port):
            messagebox.showinfo("Успех", "Подключение к серверу установлено!")
        else:
            messagebox.showerror("Ошибка", "Сервер недоступен.")

    def download_certificate(self):
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showwarning("Ошибка", "Введите IP-адрес сервера!")
            return
        if download_certificate_via_ftp(ip):
            messagebox.showinfo("Успех", "Сертификат успешно загружен!")

    def generate_keys(self):
        public_key = generate_rsa_keys()
        if public_key:
            messagebox.showinfo("Успех", "Ключи успешно сгенерированы!")

    def print_file(self):
        if not self.decrypted_file_path:
            messagebox.showwarning("Внимание", "Файл для печати не найден. Сначала получите файл.")
            return
        try:
            if os.name == "nt":  # Windows
                import win32api
                win32api.ShellExecute(0, "print", self.decrypted_file_path, None, ".", 0)
            else:
                messagebox.showwarning("Внимание", "Печать доступна только на Windows.")
            messagebox.showinfo("Успех", "Файл отправлен на печать!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось выполнить печать: {e}")

    def receive_and_decrypt(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not ip or not port:
            messagebox.showwarning("Ошибка", "Заполните все поля!")
            return
        private_key = load_private_key()
        if private_key is None:
            return
        decrypted_path = receive_and_decrypt_file(ip, port, private_key)
        if decrypted_path:
            self.decrypted_file_path = decrypted_path

# Получение файла с сервера и его расшифровка
def receive_and_decrypt_file(host, port, private_key):
    try:
        if not os.path.exists("server.crt"):
            messagebox.showerror("Ошибка", "Сертификат сервера не найден.")
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile="server.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True

        with socket.create_connection((host, int(port)), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Получение зашифрованного AES-ключа
                encrypted_aes_key_len = int.from_bytes(ssock.recv(4), "big")
                encrypted_aes_key = ssock.recv(encrypted_aes_key_len)
                # Получение IV
                iv = ssock.recv(16)
                # Получение шифротекста
                ciphertext = ssock.recv(4096)

        aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
        if aes_key is None:
            return None

        # Временно сохраняем полученный файл, чтобы получить корректный file_path
        temp_encrypted_path = "received_file.enc"
        with open(temp_encrypted_path, "wb") as f:
            f.write(iv + ciphertext)

        # Теперь передаем file_path в decrypt_file
        new_path = decrypt_file(temp_encrypted_path, iv, ciphertext, aes_key)
        os.remove(temp_encrypted_path)  # Удаляем временный .enc файл
        return new_path

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось получить или расшифровать файл: {e}")
        return None

    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось получить или расшифровать файл: {e}")
        return None

if __name__ == "__main__":
    root = Tk()
    app = App(root)
    root.mainloop()
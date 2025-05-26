import os
import socket
from ssl import SSLContext, PROTOCOL_TLS_CLIENT, CERT_REQUIRED
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import messagebox, scrolledtext
from ftplib import FTP


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


# Генерация ключей RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()

    # Сохранение приватного ключа
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
    )


# Расшифровка AES ключа с помощью RSA
def decrypt_aes_key(encrypted_aes_key, private_key):
    try:
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return aes_key
    except Exception as e:
        raise ValueError(f"Не удалось расшифровать AES-ключ: {e}")


# Расшифровка файла с помощью AES
def decrypt_file(iv, ciphertext, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Удаление PKCS7 padding
    padding_length = plaintext[-1]
    if not (1 <= padding_length <= 16):
        raise ValueError("Неверный формат PKCS7 padding")
    plaintext = plaintext[:-padding_length]

    return plaintext


# Получение файла с сервера и его расшифровка
def receive_and_decrypt_file(host, port, private_key):
    try:
        if not os.path.exists("server.crt"):
            messagebox.showerror("Ошибка", "Сертификат сервера не найден.")
            return

        context = SSLContext(PROTOCOL_TLS_CLIENT)
        context.load_verify_locations("server.crt")
        context.verify_mode = CERT_REQUIRED

        with socket.create_connection((host, int(port))) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Получение зашифрованного AES-ключа
                encrypted_aes_key_len = int.from_bytes(ssock.recv(4), "big")
                if encrypted_aes_key_len <= 0 or encrypted_aes_key_len > 512:
                    raise ValueError("Неверная длина AES-ключа")
                encrypted_aes_key = ssock.recv(encrypted_aes_key_len)

                # Получение IV
                iv_len = int.from_bytes(ssock.recv(4), "big")
                if iv_len != 16:
                    raise ValueError("Неверная длина IV")
                iv = ssock.recv(iv_len)

                # Получение данных
                ciphertext_len = int.from_bytes(ssock.recv(4), "big")
                if ciphertext_len <= 0:
                    raise ValueError("Неверная длина данных")
                ciphertext = ssock.recv(ciphertext_len)

                file_extension = ssock.recv(4).decode().strip('\x00')  # Безопасное удаление нулевых символов

                # Расшифровка AES-ключа
                aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

                # Расшифровка файла
                plaintext = decrypt_file(iv, ciphertext, aes_key)

                # Сохранение расшифрованного файла
                output_path = f"decrypted_file{file_extension}"
                with open(output_path, "wb") as f:
                    f.write(plaintext)

                messagebox.showinfo("Успех", f"Файл успешно расшифрован как {output_path}")
                return output_path

    except FileNotFoundError:
        messagebox.showerror("Ошибка", "Приватный ключ или сертификат не найдены.")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось получить и расшифровать файл: {e}")
    return None


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


# Интерфейс программы
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Клиент")
        self.root.geometry("800x600")
        self.root.configure(bg="#444")

        center_frame = tk.Frame(root, bg="#444")
        center_frame.pack(expand=True, padx=20, pady=20)

        # IP Entry
        self.ip_entry = tk.Entry(center_frame, width=30, fg="gray")
        self.ip_entry.insert(0, "Введите IP-адрес сервера")
        self.ip_entry.bind("<FocusIn>", self.clear_ip_placeholder)
        self.ip_entry.bind("<FocusOut>", self.add_ip_placeholder)
        self.ip_entry.grid(row=0, column=0, pady=5, padx=10, sticky="w")

        # Port Entry
        self.port_entry = tk.Entry(center_frame, width=30, fg="gray")
        self.port_entry.insert(0, "Введите порт сервера")
        self.port_entry.bind("<FocusIn>", self.clear_port_placeholder)
        self.port_entry.bind("<FocusOut>", self.add_port_placeholder)
        self.port_entry.grid(row=1, column=0, pady=5, padx=10, sticky="w")

        # Кнопки
        tk.Button(center_frame, text="Получить сертификат", command=self.download_certificate,
                  bg="#555", fg="white").grid(row=2, column=0, pady=10)
        tk.Button(center_frame, text="Подключиться к серверу", command=self.connect_to_server,
                  bg="#555", fg="white").grid(row=3, column=0, pady=10)

        buttons_frame = tk.Frame(center_frame, bg="#444")
        buttons_frame.grid(row=4, column=0, pady=10)

        buttons_left = [
            ("Сгенерировать ключи", self.generate_keys),
            ("Получить файл от сервера", self.receive_and_decrypt),
        ]
        buttons_right = [
            ("Печать файла", self.print_file),
        ]

        for i, (text, command) in enumerate(buttons_left):
            tk.Button(buttons_frame, text=text, command=command, bg="#555", fg="white").grid(
                row=i, column=0, pady=5, padx=5, sticky="ew"
            )
        for i, (text, command) in enumerate(buttons_right):
            tk.Button(buttons_frame, text=text, command=command, bg="#555", fg="white").grid(
                row=i, column=1, pady=5, padx=5, sticky="ew"
            )

        self.decrypted_file_path = None

    def clear_ip_placeholder(self, event):
        if self.ip_entry.get() == "Введите IP-адрес сервера":
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.config(fg="black")

    def add_ip_placeholder(self, event):
        if not self.ip_entry.get():
            self.ip_entry.insert(0, "Введите IP-адрес сервера")
            self.ip_entry.config(fg="gray")

    def clear_port_placeholder(self, event):
        if self.port_entry.get() == "Введите порт сервера":
            self.port_entry.delete(0, tk.END)
            self.port_entry.config(fg="black")

    def add_port_placeholder(self, event):
        if not self.port_entry.get():
            self.port_entry.insert(0, "Введите порт сервера")
            self.port_entry.config(fg="gray")

    def download_certificate(self):
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showwarning("Ошибка", "Введите IP-адрес сервера!")
            return
        if download_certificate_via_ftp(ip):
            messagebox.showinfo("Успех", "Сертификат успешно загружен!")

    def connect_to_server(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not ip or not port:
            messagebox.showwarning("Ошибка", "Заполните все поля!")
            return
        try:
            sock = socket.create_connection((ip, int(port)), timeout=2)
            sock.close()
            messagebox.showinfo("Успех", "Подключение к серверу установлено!")
        except (socket.timeout, ConnectionRefusedError):
            messagebox.showerror("Ошибка", "Сервер недоступен.")

    def generate_keys(self):
        public_key = generate_rsa_keys()
        messagebox.showinfo("Успех", "Ключи успешно сгенерированы!")

        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not ip or not port:
            messagebox.showwarning("Ошибка", "Заполните все поля!")
            return

        try:
            context = SSLContext(PROTOCOL_TLS_CLIENT)
            context.load_verify_locations("server.crt")
            context.verify_mode = CERT_REQUIRED

            with socket.create_connection((ip, int(port))) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.sendall(public_key)

            messagebox.showinfo("Успех", "Публичный ключ отправлен на сервер!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось отправить публичный ключ: {e}")

    def receive_and_decrypt(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not ip or not port:
            messagebox.showwarning("Ошибка", "Заполните все поля!")
            return
        private_key = load_private_key()
        if not private_key:
            return
        self.decrypted_file_path = receive_and_decrypt_file(ip, port, private_key)

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
                return
            messagebox.showinfo("Успех", "Файл отправлен на печать!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось выполнить печать: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
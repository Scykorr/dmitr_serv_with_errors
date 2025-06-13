import os
import socket
from ftplib import FTP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import ssl
from tkinter import filedialog, messagebox, scrolledtext, ttk, Tk, Frame, Label, Entry, Button, END
import tkinter as tk


# Загрузка публичного ключа
def load_public_key(file_path):
    try:
        with open(file_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Загруженный ключ не является RSA-ключом.")
        return public_key
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл {file_path} не найден.")
    except Exception as e:
        raise ValueError(f"Ошибка при загрузке ключа: {e}")


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
    ).decode()


# Шифрование файла с помощью AES
def encrypt_file(file_path, aes_key, encrypted_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, "rb") as f:
        plaintext = f.read()
    # Добавляем PKCS7 padding
    padding_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_len]) * padding_len
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Сохраняем: длина ключа (4 байта), ключ, IV, шифротекст
    with open(file_path + ".enc", "wb") as f:
        f.write(len(encrypted_key).to_bytes(4, "big"))
        f.write(encrypted_key)
        f.write(iv)
        f.write(ciphertext)
    os.remove(file_path)


# Расшифровка файла с помощью AES
def decrypt_file(file_path, aes_key):
    with open(file_path, "rb") as f:
        data = f.read()

    offset = 0
    key_length = int.from_bytes(data[offset:offset+4], byteorder='big')
    offset += 4
    encrypted_aes_key = data[offset:offset+key_length]
    offset += key_length
    iv = data[offset:offset+16]
    offset += 16
    ciphertext = data[offset:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_length]

    new_path = file_path.replace(".enc", "_decrypted.docx")
    with open(new_path, "wb") as f:
        f.write(plaintext)
    os.remove(file_path)
    return new_path


# Расшифровка AES-ключа с помощью RSA
def decrypt_aes_key(encrypted_key):
    try:
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
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
        messagebox.showerror("Ошибка", f"Не удалось расшифровать ключ: {e}")
        return None


# Отправка файла через TLS
def send_file(ip, port, file_path, public_key, progress_callback=None):
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cafile="server.crt")
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        with socket.create_connection((ip, int(port))) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                ssock.sendall(len(encrypted_key).to_bytes(4, "big"))
                ssock.sendall(encrypted_key)
                with open(file_path, "rb") as f:
                    file_data = f.read()
                ssock.sendall(file_data)
        for i in range(100):
            progress_callback(i + 1)
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
        sock = socket.create_connection((ip, int(port)), timeout=2)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False


# Интерфейс
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Клиент")
        self.root.geometry("800x600")
        self.root.configure(bg="#444")
        center_frame = Frame(root, bg="#444")
        center_frame.pack(expand=True, padx=20, pady=20)

        Label(center_frame, text="IP-адрес сервера:", bg="#444", fg="white").grid(row=0, column=0, sticky="w")
        self.ip_entry = Entry(center_frame, width=30)
        self.ip_entry.insert(0, "localhost")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)

        Label(center_frame, text="Порт сервера:", bg="#444", fg="white").grid(row=1, column=0, sticky="w")
        self.port_entry = Entry(center_frame, width=30)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=1, column=1, padx=10, pady=5)

        Button(center_frame, text="Подключиться к серверу", command=self.connect_to_server, bg="#555", fg="white").grid(
            row=2, column=0, columnspan=2, pady=10)

        buttons_frame = Frame(center_frame, bg="#444")
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=10)

        buttons = [
            ("Выбрать файл", self.select_file),
            ("Зашифровать файл", self.encrypt_selected_file),
            ("Отправить файл (TLS)", self.send_encrypted_file),
            ("Расшифровать файл", self.decrypt_selected_file),
            ("Сгенерировать ключи", self.generate_keys),
            ("Получить сертификат", self.download_certificate),
        ]

        for i, (text, command) in enumerate(buttons):
            Button(buttons_frame, text=text, command=command, bg="#555", fg="white").grid(
                row=i, column=0, pady=5, padx=5, sticky="ew"
            )

        Label(center_frame, text="Публичный ключ:", bg="#444", fg="white").grid(row=4, column=0, sticky="w")
        self.key_text = scrolledtext.ScrolledText(center_frame, width=60, height=10, wrap="word")
        self.key_text.grid(row=5, column=0, columnspan=2, padx=10, pady=5)

        self.progress = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(center_frame, variable=self.progress, maximum=100, length=400)
        self.progress_bar.grid(row=6, column=0, columnspan=2, pady=10)

        self.file_path = None

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

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Выберите Word-документ",
                                               filetypes=[("Word Documents", "*.docx *.doc")])
        if file_path:
            self.file_path = file_path
            messagebox.showinfo("Файл выбран", f"Выбран файл: {self.file_path}")

    def encrypt_selected_file(self):
        if not self.file_path:
            messagebox.showwarning("Ошибка", "Файл не выбран!")
            return
        try:
            public_key = load_public_key("public_key.pem")
        except FileNotFoundError:
            messagebox.showerror("Ошибка", "Публичный ключ не найден. Сгенерируйте ключи.")
            return

        aes_key = os.urandom(32)
        encrypted_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        encrypt_file(self.file_path, aes_key, encrypted_key)
        messagebox.showinfo("Успех", "Файл успешно зашифрован!")

    def decrypt_selected_file(self):
        if not self.file_path:
            messagebox.showwarning("Ошибка", "Файл не выбран!")
            return
        try:
            with open(self.file_path + '.enc', 'rb') as f:
                data = f.read()

            offset = 0
            key_length = int.from_bytes(data[offset:offset+4], byteorder='big')
            offset += 4
            encrypted_aes_key = data[offset:offset+key_length]
            offset += key_length
            iv = data[offset:offset+16]
            offset += 16
            ciphertext = data[offset:]

            aes_key = decrypt_aes_key(encrypted_aes_key)
            if aes_key is None:
                return

            new_path = self.decrypt_file_manually(self.file_path, ciphertext, iv, aes_key)
            messagebox.showinfo("Успех", f"Файл сохранён как {new_path}")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось расшифровать файл: {e}")

    @staticmethod
    def decrypt_file_manually(file_path, ciphertext, iv, aes_key):
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            padding_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-padding_length]
            new_path = file_path.replace(".enc", "_decrypted.docx")
            with open(new_path, "wb") as f:
                f.write(plaintext)
            return new_path
        except Exception as e:
            raise RuntimeError(f"Ошибка при расшифровке: {e}")

    def send_encrypted_file(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        if not ip or not port or not self.file_path:
            messagebox.showwarning("Ошибка", "Заполните все поля!")
            return
        try:
            public_key = load_public_key("public_key.pem")
        except FileNotFoundError:
            messagebox.showerror("Ошибка", "Публичный ключ не найден. Сгенерируйте ключи.")
            return
        send_file(ip, port, self.file_path, public_key, self.update_progress)

    def generate_keys(self):
        public_key = generate_rsa_keys()
        self.key_text.delete(1.0, END)
        self.key_text.insert(END, public_key)
        messagebox.showinfo("Успех", "Ключи успешно сгенерированы!")

    def download_certificate(self):
        ip = self.ip_entry.get()
        if not ip:
            messagebox.showwarning("Ошибка", "Введите IP-адрес сервера!")
            return
        if download_certificate_via_ftp(ip):
            messagebox.showinfo("Успех", "Сертификат успешно загружен!")

    def update_progress(self, value):
        self.progress.set(value)
        self.root.update_idletasks()


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
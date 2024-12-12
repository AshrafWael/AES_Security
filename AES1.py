import os
from tkinter import Tk, Label, Button, filedialog, StringVar, OptionMenu
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_key():
    """Generate a random 32-byte AES key."""
    return os.urandom(32)

def encrypt_image(image_path, key, mode):
    """Encrypt an image using AES in the specified mode."""
    with open(image_path, "rb") as f:
        image_data = f.read()

    # Padding the data to match AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    iv = os.urandom(16)
    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    else:
        raise ValueError("Unsupported mode")

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv

def decrypt_image(ciphertext, key, iv, mode):
    """Decrypt an image using AES in the specified mode."""
    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    else:
        raise ValueError("Unsupported mode")

    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Removing padding
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data

def save_image(data, output_path):
    """Save the binary data as an image."""
    with open(output_path, "wb") as f:
        f.write(data)

def save_binary(data, output_path):
    """Save binary data to a file."""
    with open(output_path, "wb") as f:
        f.write(data)

def load_binary(input_path):
    """Load binary data from a file."""
    with open(input_path, "rb") as f:
        return f.read()

# GUI Implementation
class AESImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Image Encryptor")

        self.key = generate_key()
        self.mode = StringVar()
        self.mode.set("ECB")

        Label(root, text="AES Image Encryptor and Decryptor").pack()
        self.image_label = Label(root)
        self.image_label.pack()

        Button(root, text="Select Image or Encrypted File", command=self.load_image).pack()
        Button(root, text="Encrypt Image", command=self.encrypt_image).pack()
        Button(root, text="Decrypt Image", command=self.decrypt_image).pack()

        modes_menu = OptionMenu(root, self.mode, "ECB", "CBC", "CTR")
        modes_menu.pack()

        self.file_path = None
        self.iv = None

    def load_image(self):
        # Allow both image files and .bin files
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg"), ("Binary Files", "*.bin")])
        if file_path:
            self.file_path = file_path

            # Check if the file is an image or binary file
            if file_path.endswith('.bin'):
                Label(self.root, text="Binary file selected for decryption.").pack()
            else:
                try:
                    # It's an image file, so load and display it
                    image = Image.open(file_path)
                    image.thumbnail((300, 300))
                    photo = ImageTk.PhotoImage(image)
                    self.image_label.config(image=photo)
                    self.image_label.image = photo
                except Exception as e:
                    Label(self.root, text="Error loading image: " + str(e)).pack()

    def encrypt_image(self):
        if self.file_path:
            mode = self.mode.get()
            ciphertext, self.iv = encrypt_image(self.file_path, self.key, mode)
            save_binary(ciphertext, "encrypted_image.bin")
            Label(self.root, text="Image Encrypted and Saved as 'encrypted_image.bin'").pack()

    def decrypt_image(self):
        if self.file_path:
            mode = self.mode.get()
            ciphertext = load_binary("encrypted_image.bin")
            plaintext = decrypt_image(ciphertext, self.key, self.iv, mode)
            save_image(plaintext, "decrypted_image.png")
            Label(self.root, text="Image Decrypted and Saved as 'decrypted_image.png'").pack()

if __name__ == "__main__":
    root = Tk()
    app = AESImageEncryptorApp(root)
    root.mainloop()

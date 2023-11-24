import tkinter as tk
from tkinter import filedialog, messagebox
import cv2
import os
import string
from tkinter import simpledialog

class ImageSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography")
        self.secret_message = ""
        self.file_path = tk.StringVar()
        self.root.geometry("250x250")

        # Entry for file path
        self.file_entry = tk.Entry(root, textvariable=self.file_path, state='disabled')
        self.file_entry.pack()

        # Browse button
        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.pack()

        # Entry for secret message
        self.secret_message_label = tk.Label(root, text="Enter Secret Message:")
        self.secret_message_label.pack()
        self.secret_message_entry = tk.Entry(root)
        self.secret_message_entry.pack()

        # Password entry
        self.password_label = tk.Label(root, text="Enter password:")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        # Encrypt button
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_image)
        self.encrypt_button.pack()

        # Decrypt button
        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_image)
        self.decrypt_button.pack()

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        if file_path:
            self.file_path.set(file_path)

    def encrypt_image(self):
        try:
            img_path = self.file_path.get()
            if not img_path:
                messagebox.showwarning("Warning", "Please select an image file.")
                return

            self.secret_message = self.secret_message_entry.get()
            password = self.password_entry.get()

            img = cv2.imread(img_path)

            d = {char: i for i, char in enumerate(string.printable)}

            m, n, z = 0, 0, 0

            for char in self.secret_message:
                img[n, m, z] = d[char]
                n, m, z = n + 1, m + 1, (z + 1) % 3

            encrypted_img_path = "encryptedImage.png"
            cv2.imwrite(encrypted_img_path, img)

            messagebox.showinfo("Encryption", f"Image encrypted and saved as '{encrypted_img_path}'")
        except Exception as e:
            messagebox.showerror("Error", f"Unable to encrypt image. {str(e)}")

    def decrypt_image(self):
        try:
        # Ask for the encrypted image file
            encrypted_img_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
            if not encrypted_img_path:
                return

        # Ask for the password used during encryption
            password = simpledialog.askstring("Password", "Enter passcode for decryption:", show='*')
            if not password:
                return

            img = cv2.imread(encrypted_img_path)

            d = {i: char for i, char in enumerate(string.printable)}

            n, m, z = 0, 0, 0
            message = ""

            for _ in range(len(self.secret_message)):
                message += d[img[n, m, z]]
                n, m, z = n + 1, m + 1, (z + 1) % 3

        # Check if the entered password matches the original password used for encryption
            if password == self.password_entry.get():
                messagebox.showinfo("Decryption", f"Decrypted message: {message}")
            else:
                messagebox.showerror("Error", "Incorrect password")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageSteganographyApp(root)
    root.mainloop()

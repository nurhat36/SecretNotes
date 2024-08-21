import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet
import base64

window = tk.Tk()
window.title("Secret Notes")
window.minsize(width=450, height=600)

photo = tk.PhotoImage(file="71sRuw-7EBL._AC_UF1000,1000_QL80_.png")  # Dosya yolunu kendi resminize göre ayarlayın
label = tk.Label(window, image=photo)
label.pack()

ilk_label = tk.Label(text="Enter your title", font=("arial", 10, "italic"))
ilk_label.config(bg="black", fg="white")
ilk_label.pack()
title_entry = tk.Entry(width=20)
title_entry.pack()

label2 = tk.Label(text="Enter your secret", font=("arial", 10, "italic"))
label2.config(bg="black", fg="white")
label2.pack()

text_widget = tk.Text(window, height=10, width=50)
text_widget.pack(padx=10, pady=10)

ilk_label = tk.Label(text="Enter master key", font=("arial", 10, "italic"))
ilk_label.config(bg="black", fg="white")
ilk_label.pack()
key_entry = tk.Entry(width=20, show="*")
key_entry.pack()


def generate_key(password):
    # Şifreyi bir anahtar olarak kullanıyoruz
    password_bytes = password.encode()
    # Fernet anahtarı oluşturma (32 baytlık URL güvenli base64 kodlu anahtar)
    key = base64.urlsafe_b64encode(password_bytes.ljust(32)[:32])
    return key


def save_click_button():
    title = title_entry.get()
    secret = text_widget.get("1.0", tk.END).strip()
    password = key_entry.get()

    if not title or not secret or not password:
        messagebox.showerror("Error", "All fields must be filled!")
        return

    key = generate_key(password)
    cipher = Fernet(key)
    encrypted_note = cipher.encrypt(secret.encode())

    with open(f"{title}.txt", "wb") as file:
        file.write(encrypted_note)

    messagebox.showinfo("Saved", "Your note has been encrypted and saved!")


def decrypt_click_button():
    title = title_entry.get()
    password = key_entry.get()

    if not title or not password:
        messagebox.showerror("Error", "Title and master key must be provided!")
        return

    try:
        key = generate_key(password)
        cipher = Fernet(key)

        with open(f"{title}.txt", "rb") as file:
            encrypted_note = file.read()

        decrypted_note = cipher.decrypt(encrypted_note).decode()

        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, decrypted_note)

        messagebox.showinfo("Decrypted", "Your note has been decrypted!")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed. {str(e)}")


def open_file():
    file_path = filedialog.askopenfilename(title="Select a file", filetypes=[("Text files", "*.txt")])

    if not file_path:
        return

    password = key_entry.get()

    if not password:
        messagebox.showerror("Error", "Master key must be provided!")
        return

    try:
        key = generate_key(password)
        cipher = Fernet(key)

        with open(file_path, "rb") as file:
            encrypted_note = file.read()

        decrypted_note = cipher.decrypt(encrypted_note).decode()

        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, decrypted_note)

        messagebox.showinfo("Decrypted", "Your note has been decrypted and opened!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open or decrypt the file. {str(e)}")


save_button = tk.Button(text="Save & Encrypt", command=save_click_button)
save_button.pack()

decrypt_button = tk.Button(text="Decrypt", command=decrypt_click_button)
decrypt_button.pack()

open_button = tk.Button(text="Open & Decrypt File", command=open_file)
open_button.pack()

window.mainloop()

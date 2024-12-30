import tkinter as tk
from tkinter import messagebox

def caesar_cipher(message, shift, mode='encrypt'):
    result = ''
    if mode == 'decrypt':
        shift = -shift

    for char in message:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char

    return result


def vigenere_cipher(message, key, mode='encrypt'):
    result = ''
    key_length = len(key)
    key_as_int = [ord(i) - ord('A') for i in key.upper()]
    message_int = [ord(i) - ord('A') for i in message.upper()]
    
    for i in range(len(message_int)):
        if message[i].isalpha():
            if mode == 'decrypt':
                value = (message_int[i] - key_as_int[i % key_length]) % 26
            else:
                value = (message_int[i] + key_as_int[i % key_length]) % 26
            result += chr(value + ord('A'))
        else:
            result += message[i]

    return result


def process():
    message = entry_message.get()
    cipher_type = cipher_var.get()
    mode = mode_var.get()
    
    if cipher_type == "Caesar":
        try:
            shift = int(entry_key.get())
            if mode == "Encrypt":
                result = caesar_cipher(message, shift, 'encrypt')
            else:
                result = caesar_cipher(message, shift, 'decrypt')
        except ValueError:
            messagebox.showerror("Input Error", "Please enter a valid integer for the shift.")
            return
            
    elif cipher_type == "Vigenère":
        key = entry_key.get()
        if mode == "Encrypt":
            result = vigenere_cipher(message, key, 'encrypt')
        else:
            result = vigenere_cipher(message, key, 'decrypt')
    
    output_var.set(result)


# Create the main window
root = tk.Tk()
root.title("Encryption and Decryption Tool")

# Input Message
tk.Label(root, text="Enter Message:").grid(row=0, column=0)
entry_message = tk.Entry(root, width=50)
entry_message.grid(row=0, column=1)

# Cipher Type Selection
cipher_var = tk.StringVar(value="Caesar")
tk.Label(root, text="Select Cipher:").grid(row=1, column=0)
tk.Radiobutton(root, text="Caesar", variable=cipher_var, value="Caesar").grid(row=1, column=1)
tk.Radiobutton(root, text="Vigenère", variable=cipher_var, value="Vigenère").grid(row=1, column=2)

# Key/Shift Input
tk.Label(root, text="Enter Key/Shift:").grid(row=2, column=0)
entry_key = tk.Entry(root)
entry_key.grid(row=2, column=1)

# Mode Selection
mode_var = tk.StringVar(value="Encrypt")
tk.Label(root, text="Select Mode:").grid(row=3, column=0)
tk.Radiobutton(root, text="Encrypt", variable=mode_var, value="Encrypt").grid(row=3, column=1)
tk.Radiobutton(root, text="Decrypt", variable=mode_var, value="Decrypt").grid(row=3, column=2)

# Process Button
tk.Button(root, text="Process", command=process).grid(row=4, columnspan=3)

# Output Result
output_var = tk.StringVar()
tk.Label(root, text="Result:").grid(row=5, column=0)
output_label = tk.Label(root, textvariable=output_var)
output_label.grid(row=5, column=1)

# Start the GUI event loop
root.mainloop()

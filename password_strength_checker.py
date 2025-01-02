import tkinter as tk
from tkinter import messagebox
import re

MIN_LENGTH = 8
STRENGTH_MESSAGES = {
    "weak": "Weak: {}",
    "strong": "Strong: Your password is strong."
}

def check_password_strength(password):
    """Check the strength of the password."""
    if len(password) < MIN_LENGTH:
        return STRENGTH_MESSAGES["weak"].format(f"Password is too short (minimum {MIN_LENGTH} characters).")
    
    if not any(char.islower() for char in password):
        return STRENGTH_MESSAGES["weak"].format("Password must contain at least one lowercase letter.")
    
    if not any(char.isupper() for char in password):
        return STRENGTH_MESSAGES["weak"].format("Password must contain at least one uppercase letter.")
    
    if not any(char.isdigit() for char in password):
        return STRENGTH_MESSAGES["weak"].format("Password must contain at least one digit.")
    
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return STRENGTH_MESSAGES["weak"].format("Password must contain at least one special character.")
    
    return STRENGTH_MESSAGES["strong"]

def evaluate_password():
    """Evaluate the entered password and display the result."""
    password = entry.get()
    strength = check_password_strength(password)
    messagebox.showinfo("Password Strength", strength)

def toggle_password_visibility():
    """Toggle the visibility of the password."""
    if entry.cget('show') == '*':
        entry.config(show='')
        show_password_button.config(text='Hide Password')
    else:
        entry.config(show='*')
        show_password_button.config(text='Show Password')

root = tk.Tk()
root.title("Password Strength Checker")

label = tk.Label(root, text="Enter your password:")
label.grid(row=0, column=0, padx=10, pady=10)

entry = tk.Entry(root, show='*', width=30)
entry.grid(row=1, column=0, padx=10, pady=5)

check_button = tk.Button(root, text="Check Strength", command=evaluate_password)
check_button.grid(row=2, column=0, padx=10, pady=20)

show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility)
show_password_button.grid(row=3, column=0, padx=10, pady=5)


root.mainloop()

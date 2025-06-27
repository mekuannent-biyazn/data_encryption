from tkinter import *
from cryptography.fernet import Fernet
from tkinter import messagebox, Label
import hashlib
import re

# Attempt to import MD4 from PyCryptodome, fallback to pure Python implementation
try:
    from Crypto.Hash import MD4
    def hash_md4(data):
        h = MD4.new()
        h.update(data.encode())
        return h.hexdigest()
except ImportError:
    # Pure-Python MD4 implementation
    def hash_md4(data):
        # Minimal MD4 implementation
        import struct
        # Constants
        _s = [3, 7, 11, 19] * 4 + [3, 5, 9, 13] * 4 + [3, 9, 11, 15] * 4
        _X = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
        # F, G, H functions
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & y) | (x & z) | (y & z)
        H = lambda x, y, z: x ^ y ^ z

        msg = data.encode('utf-8')
        orig_len_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
        msg += b'\x80'
        while (len(msg) % 64) != 56:
            msg += b'\x00'
        msg += struct.pack('<Q', orig_len_bits)

        A, B, C, D = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
        for chunk_ofs in range(0, len(msg), 64):
            X = list(struct.unpack('<16I', msg[chunk_ofs:chunk_ofs+64]))
            AA, BB, CC, DD = A, B, C, D
            # Round 1
            for i in range(16):
                k = i
n = _s[i]
                A = _X((A + F(B, C, D) + X[k]) & 0xFFFFFFFF, n)
                A, B, C, D = D, A, B, C
            # Round 2
            for i in range(16):
                k = (i % 4) * 4 + i // 4
n = _s[16 + i]
                A = _X((A + G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, n)
                A, B, C, D = D, A, B, C
            # Round 3
            for i in range(16):
                k = [0, 8, 4, 12][i % 4] + (i // 4)
n = _s[32 + i]
                A = _X((A + H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, n)
                A, B, C, D = D, A, B, C
            A = (A + AA) & 0xFFFFFFFF
            B = (B + BB) & 0xFFFFFFFF
            C = (C + CC) & 0xFFFFFFFF
            D = (D + DD) & 0xFFFFFFFF
        return ''.join(f"{x:02x}" for x in struct.pack('<4I', A, B, C, D))

# Other hashing functions
def hash_md5(data):
    return hashlib.md5(data.encode()).hexdigest()

def hash_sha224(data):
    return hashlib.sha224(data.encode()).hexdigest()

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def hash_sha512(data):
    return hashlib.sha512(data.encode()).hexdigest()

# Validation functions
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_ethiopian_phone(phone):
    pattern = r'^(?:\+251|0)?9\d{8}$'
    return re.match(pattern, phone)

def department(dept_val):
    dept_regex = r'^[a-zA-Z]+'
    if len(dept_val) < 4:
        return False
    return re.match(dept_regex, dept_val)

def validate_password(password):
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[\W_]', password):
        return False
    return True

# Display hashed data
def show_hashed_data(data_dict):
    display_window = Toplevel(window)
    display_window.title("Hashed Data")
    display_window.geometry("700x600")
    display_window.configure(bg="#f0f4f8")

    Label(display_window,
          text="Hashed User Data",
          font=("Cambria", 24, "bold"),
          bg="#f0f4f8",
          fg="#0000ff").pack(pady=20)

    for key, value in data_dict.items():
        Label(display_window,
              text=f"{key}:\n{value}",
              font=("Cambria", 14),
              bg="#f0f4f8",
              fg="#333333").pack(anchor="w", padx=20, pady=5)

# Save function
def save():
    name_value = nameent.get().strip()
    lname_value = lnameent.get().strip()
    empig_value = empmeent.get().strip()
    email_value = emmeent.get().strip()
    phone_value = phonent.get().strip()
    dept_value = depent.get().strip()
    age_value = entr.get()
    password_value = passent.get()
    role_value = role_var.get()
    marital_value = marital_var.get()

    # Validations...
    if not name_value:
        messagebox.showerror("Missing First Name", "First Name is required.")
        return
    if not lname_value:
        messagebox.showerror("Missing Last Name", "Last Name is required.")
        return
    if not empig_value:
        messagebox.showerror("Missing EmployID", "EmployID is necessary")
        return
    if not validate_email(email_value):
        messagebox.showerror("Invalid Email", "Please enter a valid email address.")
        return
    if not validate_ethiopian_phone(phone_value):
        messagebox.showerror("Invalid Phone", "Enter valid Ethiopian phone number starting with +251 or 09.")
        return
    if not department(dept_value):
        messagebox.showerror("Invalid Department", "Department must be at least 4 characters long.")
        return
    if not validate_password(password_value):
        messagebox.showerror(
            "Weak Password",
            "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character."
        )
        return
    if not marital_value:
        messagebox.showerror("Marital Status Not Selected", "Please select your Marital Status.")
        return
    if role_value == role_options[0]:
        messagebox.showerror("Role Not Selected", "Please select your role.")
        return

    hashed_data = {
        "First Name (MD4)": hash_md4(name_value),
        "Last Name (MD5)": hash_md5(lname_value),
        "EmployID (SHA-224)": hash_sha224(empig_value),
        "Email (SHA-256)": hash_sha256(email_value),
        "Phone (SHA-512)": hash_sha512(phone_value),
        "Department (MD4)": hash_md4(dept_value),
        "Age (MD5)": hash_md5(str(age_value)),
        "Password (SHA-256)": hash_sha256(password_value),
        "Role (SHA-224)": hash_sha224(role_value),
        "Marital Status (SHA-512)": hash_sha512(marital_value)
    }

    show_hashed_data(hashed_data)
    messagebox.showinfo("Success", "Registered successfully!")

# Clear function

def clear():
    nameent.delete(0, END)
    lnameent.delete(0, END)
    empmeent.delete(0, END)
    emmeent.delete(0, END)
    phonent.delete(0, END)
    depent.delete(0, END)
    entr.set(18)
    passent.delete(0, END)
    role_var.set(role_options[0])
    marital_var.set(None)

# Exit

def exit_app():
    window.quit()

# Main window
window = Tk()
window.geometry('900x1000')
window.title("User Interface with Two Frames")
window.configure(bg="#f0f4f8")

# Menus unchanged
mymenu = Menu(window)
window.config(menu=mymenu)
file_menu = Menu(mymenu)
mymenu.add_cascade(menu=file_menu, label='File')
file_menu.add_command(label='Open')
file_menu.add_separator()
file_menu.add_command(label='Create')
file_menu.add_command(label='Open')
file_menu.add_command(label="Exit", command=exit_app)
window_menu = Menu(mymenu)
mymenu.add_cascade(menu=window_menu, label='Window')
window_menu.add_command(label='Layout')
window_menu.add_separator()
window_menu.add_command(label="Active layout")
Navigate_menu = Menu(mymenu)
mymenu.add_cascade(menu=Navigate_menu, label='Navigate')
Navigate_menu.add_command(label='<--Back')
Navigate_menu.add_separator()
Navigate_menu.add_command(label='search')
Run_menu = Menu(mymenu)
mymenu.add_cascade(menu=Run_menu, label='Run')
Run_menu.add_command(label='compile and run')
Run_menu.add_separator()
Run_menu.add_command(label='de_bug')

# Layout

def create_label(frame, text): return Label(frame, text=text, font=("Cambria", 20, "italic"), fg="#0000ff", bg="#f0f4f8")

def create_entry(frame, width=25): return Entry(frame, font=("Cambria", 20, "italic"), bg="white", fg="#0000ff", relief=SOLID, bd=2, width=width)

right_frame = Frame(window, bg="#0000ff")
right_frame.pack(side=RIGHT, fill=BOTH, expand=True)
Label(right_frame, text="Registration Form", font=("Cambria", 28, "italic bold"), bg="#0000ff", fg="#ffffff").pack(pady=15)
form_frame = Frame(right_frame, bg="#f0f4f8")
form_frame.pack(pady=3, padx=10, fill=BOTH, expand=True)

# Entries
create_label(form_frame, "FName:").grid(row=0, column=0, sticky=W, pady=3)
nameent = create_entry(form_frame); nameent.grid(row=0, column=1, sticky=W, pady=3)
create_label(form_frame, "LName:").grid(row=1, column=0, sticky=W, pady=3)
lnameent = create_entry(form_frame); lnameent.grid(row=1, column=1, sticky=W, pady=3)
create_label(form_frame, "EmployID:").grid(row=2, column=0, sticky=W, pady=3)
empmeent = create_entry(form_frame); empmeent.grid(row=2, column=1, sticky=W, pady=3)
create_label(form_frame, "Email:").grid(row=3, column=0, sticky=W, pady=3)
emmeent = create_entry(form_frame); emmeent.grid(row=3, column=1, sticky=W, pady=3)
create_label(form_frame, "Phone:").grid(row=4, column=0, sticky=W, pady=3)
phonent = create_entry(form_frame); phonent.grid(row=4, column=1, sticky=W, pady=3)
create_label(form_frame, "Department:").grid(row=5, column=0, sticky=W, pady=3)
depent = create_entry(form_frame); depent.grid(row=5, column=1, sticky=W, pady=3)
create_label(form_frame, "Age:").grid(row=6, column=0, sticky=W, pady=3)
entr = Scale(form_frame, from_=18, to=75, orient=HORIZONTAL, length=150, bg="#f0f4f8", fg="#0000ff", troughcolor="#bdc3c7", highlightthickness=0)
entr.grid(row=6, column=1, sticky=W, pady=3); entr.set(18)
create_label(form_frame, "Password:").grid(row=7, column=0, sticky=W, pady=3)
passent = Entry(form_frame, font=("Cambria", 20, "italic"), bg="white", fg="#0000ff", relief=SOLID, bd=2, width=25, show='*')
passent.grid(row=7, column=1, sticky=W, pady=3)
create_label(form_frame, "Role:").grid(row=8, column=0, sticky=W, pady=3)
role_options = ["Select your role", "student", "instructor", "dept_head", "dean"]
role_var = StringVar(value=role_options[0])
role_menu = OptionMenu(form_frame, role_var, *role_options)
role_menu.config(font=("Cambria", 20, "italic"), bg="white", fg="#0000ff", relief=SOLID, bd=2)
role_menu.grid(row=8, column=1, sticky=W, pady=3)
create_label(form_frame, "Marital Status:").grid(row=9, column=0, sticky=W, pady=3)
marital_var = StringVar()
Radiobutton(form_frame, text="Married", variable=marital_var, value="Married", font=("Cambria", 20, "italic"), bg="#f0f4f8", fg="#0000ff").grid(row=9, column=1, sticky=W)
Radiobutton(form_frame, text="Single", variable=marital_var, value="Single", font=("Cambria", 20, "italic"), bg="#f0f4f8", fg="#0000ff").grid(row=9, column=2, sticky=E)

btn_frame = Frame(form_frame, bg="#f0f4f8")
btn_frame.grid(row=10, column=0, columnspan=3, pady=15)
Button(btn_frame, text="Clear", font=("Cambria", 22, "bold"), bg="#0000ff", fg="white", relief=FLAT, command=clear).pack(side=RIGHT, padx=10)
Button(btn_frame, text="Register", font=("Cambria", 22, "bold"), bg="#0000ff", fg="white", relief=FLAT, command=save).pack(side=LEFT, padx=10)

window.mainloop()

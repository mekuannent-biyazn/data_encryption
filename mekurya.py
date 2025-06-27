from tkinter import *
from cryptography.fernet import Fernet
from tkinter import messagebox, Label
import hashlib
import re

# Hashing helpers
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_email(email):
    return hashlib.sha256(email.encode()).hexdigest()

# Validation helpers
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_ethiopian_phone(phone):
    pattern = r'^(?:\+251|0)?9\d{8}$'
    return re.match(pattern, phone)

def validate_department(dept_val):
    return len(dept_val) >= 4 and re.match(r'^[a-zA-Z]+', dept_val)

def validate_password(password):
    checks = [
        (len(password) >= 8, "length"),
        (re.search(r'[A-Z]', password), "uppercase"),
        (re.search(r'[a-z]', password), "lowercase"),
        (re.search(r'\d', password), "digit"),
        (re.search(r'[\W_]', password), "special char"),
    ]
    return all(cond for cond, _ in checks)

# Main save: validate, hash, then display in result frame
def save():
    # Gather inputs
    name_val = name_entry.get().strip()
    lname_val = lname_entry.get().strip()
    empid_val = empid_entry.get().strip()
    email_val = email_entry.get().strip()
    phone_val = phone_entry.get().strip()
    dept_val = dept_entry.get().strip()
    age_val = age_scale.get()
    pwd_val = pwd_entry.get().strip()
    role_val = role_var.get()
    marital_val = marital_var.get()

    G=Fernet.generate_key()

    # Validate required
    if not name_val or not lname_val or not empid_val:
        messagebox.showerror("Missing Data", "First, Last name and EmployID are required.")
        return
    if not validate_email(email_val):
        messagebox.showerror("Invalid Email", "Enter a valid email.")
        return
    if not validate_ethiopian_phone(phone_val):
        messagebox.showerror("Invalid Phone", "Enter valid Ethiopian phone.")
        return
    if not validate_department(dept_val):
        messagebox.showerror("Invalid Dept", "Department must be >=4 letters.")
        return
    if not validate_password(pwd_val):
        messagebox.showerror("Weak Password", "Pwd must have 8+ chars, upper, lower, digit, special.")
        return
    if role_val == role_options[0] or not marital_val:
        messagebox.showerror("Selection Missing", "Please select role and marital status.")
        return

    # Hash sensitive
    hashed_pwd = hash_password(pwd_val)
    hashed_email = hash_email(email_val)

    # Clear result frame
    for widget in result_frame.winfo_children():
        widget.destroy()

    # Display results
    Label(result_frame, text="Registration Result", font=("Cambria", 20, "bold"), fg="#ffffff", bg="#004080").pack(pady=10)
    fields = [
        ("First Name",  {Fernet(G).encrypt(name_entry.get().encode())},),
        ("Last Name", {Fernet(G).encrypt(lname_entry.get().encode())},),
        ("Employ ID", empid_val),
        ("Email (hashed)", hashed_email),
        ("Phone", hashlib.sha512(phone_entry.get().encode()).hexdigest()),
        ("Department", hashlib.sha512(dept_entry.get().encode()).hexdigest()),
        ("Age", str(age_val)),
        ("Password (hashed)", hashed_pwd),
        ("Role", role_val),
        ("Marital Status", marital_val)
    ]
    for label, val in fields:
        frame = Frame(result_frame, bg="#f0f4f8")
        frame.pack(fill=X, padx=10, pady=2)
        Label(frame, text=f"{label}:", font=("Cambria", 14, "bold"), width=15, anchor=W).pack(side=LEFT)
        Label(frame, text=val, font=("Cambria", 14), anchor=W).pack(side=LEFT)

    messagebox.showinfo("Success", "Registered successfully!")

# Clear form
def clear():
    for e in [name_entry, lname_entry, empid_entry, email_entry, phone_entry, dept_entry, pwd_entry]:
        e.delete(0, END)
    role_var.set(role_options[0])
    marital_var.set("")
    age_scale.set(18)

# Exit handler
def exit_app():
    window.quit()

# Setup window
window = Tk()
window.title("User Registration with Result Display")
window.geometry('1000x600')

# Menu
menu = Menu(window)
window.config(menu=menu)
file_menu = Menu(menu, tearoff=0)
file_menu.add_command(label='Exit', command=exit_app)
menu.add_cascade(label='File', menu=file_menu)

window_menu =Menu(menu)
menu.add_cascade(menu=window_menu,label ='Window')
window_menu.add_command(label='Layout')
window_menu.add_separator()
window_menu.add_command(label="Active layout")

Navigate_menu=Menu(menu)
menu.add_cascade(menu=Navigate_menu,label='Navigate')
Navigate_menu.add_command(label='<--Back')
Navigate_menu.add_separator()
Navigate_menu.add_command(label='search')

# Input frame
input_frame = Frame(window, bg="#f0f4f8", bd=2, relief=SOLID)
input_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
Label(input_frame, text="Registration Form", font=("Cambria", 20, "bold"), bg="#004080", fg="white").pack(fill=X)

# Form fields
entries = []
def add_field(parent, text):
    frame = Frame(parent, bg="#f0f4f8")
    frame.pack(fill=X, pady=3, padx=10)
    Label(frame, text=text, font=("Cambria", 14), width=15, anchor=W, bg="#f0f4f8").pack(side=LEFT)
    ent = Entry(frame, font=("Cambria", 14), bd=2, relief=SOLID)
    ent.pack(fill=X, expand=True)
    return ent

name_entry = add_field(input_frame, "First Name:")
lname_entry = add_field(input_frame, "Last Name:")
empid_entry = add_field(input_frame, "Employ ID:")
email_entry = add_field(input_frame, "Email:")
phone_entry = add_field(input_frame, "Phone:")
dept_entry = add_field(input_frame, "Department:")

# Age slider
frame_age = Frame(input_frame, bg="#f0f4f8")
frame_age.pack(fill=X, pady=3, padx=10)
Label(frame_age, text="Age:", font=("Cambria", 14), width=15, anchor=W, bg="#f0f4f8").pack(side=LEFT)
age_scale = Scale(frame_age, from_=18, to=75, orient=HORIZONTAL)
age_scale.pack(fill=X, expand=True)

# Password
def add_password_field(parent, text):
    frame = Frame(parent, bg="#f0f4f8")
    frame.pack(fill=X, pady=3, padx=10)
    Label(frame, text=text, font=("Cambria", 14), width=15, anchor=W, bg="#f0f4f8").pack(side=LEFT)
    ent = Entry(frame, font=("Cambria", 14), bd=2, relief=SOLID, show='*')
    ent.pack(fill=X, expand=True)
    return ent

pwd_entry = add_password_field(input_frame, "Password:")

# Role dropdown
role_options = ["Select Role", "student", "instructor", "dept_head", "dean"]
role_var = StringVar(value=role_options[0])
frame_role = Frame(input_frame, bg="#f0f4f8")
frame_role.pack(fill=X, pady=3, padx=10)
Label(frame_role, text="Role:", font=("Cambria", 14), width=15, anchor=W, bg="#f0f4f8").pack(side=LEFT)
OptionMenu(frame_role, role_var, *role_options).pack(fill=X, expand=True)

# Marital status radios
marital_var = StringVar()
frame_mar = Frame(input_frame, bg="#f0f4f8")
frame_mar.pack(fill=X, pady=3, padx=10)
Label(frame_mar, text="Marital Status:", font=("Cambria", 14), width=15, anchor=W, bg="#f0f4f8").pack(side=LEFT)
for val in ["Married", "Single"]:
    Radiobutton(frame_mar, text=val, variable=marital_var, value=val, bg="#f0f4f8").pack(side=LEFT, padx=5)

# Buttons
btn_frame = Frame(input_frame, bg="#f0f4f8")
btn_frame.pack(fill=X, pady=10)
Button(btn_frame, text="Register", command=save, font=("Cambria", 14)).pack(side=LEFT, padx=5)
Button(btn_frame, text="Clear", command=clear, font=("Cambria", 14)).pack(side=LEFT, padx=5)

# Result frame
result_frame = Frame(window, bg="#f0f4f8", bd=2, relief=SOLID)
result_frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=5, pady=5)
Label(result_frame, text="Results will appear here after registration", font=("Cambria", 16), bg="#f0f4f8").pack(pady=20)

window.mainloop()

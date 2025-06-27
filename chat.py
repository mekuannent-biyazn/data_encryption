from tkinter import *
from cryptography.fernet import Fernet
from tkinter import messagebox
import hashlib
import re

def hash_password(password):
    sha_signature = hashlib.sha256(password.encode()).hexdigest()
    return sha_signature

def md_password(password):
    md_signature = hashlib.md5(password.encode()).hexdigest()
    return md_signature

def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def phone_num(phone):
    phone_regex = r'^(?:\+251|0)?9\d{8}$'
    return re.match(phone_regex, phone)

def department(dept_val):
    dept_regx = r'^[a-zA-Z]+'
    if len(dept_val) < 4:
        return False
    return re.match(dept_regx, dept_val)

def employ(emp_val):
    empid_regx = r'^[0-9]+'
    if len(emp_val) > 8:
        return False
    return re.match(empid_regx, emp_val)

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

def Save():
    name_value = nameent.get().strip()
    lname_value = lnameent.get().strip()
    age_value = entr.get()
    password_value = passent.get()
    country_value = country_var.get()
    email_value = emmeent.get().strip()
    sex_value = sex_var.get()
    phone_value = phonent.get().strip()
    empig_value = empmeent.get().strip()
    dept_value = depent.get().strip()
    role_value = role_var.get()
    access_value = acessent.get().strip()

    if not name_value:
        messagebox.showerror("Missing First Name", "First Name is required.")
        return
    if not lname_value:
        messagebox.showinfo("Missing Last Name", "Last Name is required.")
        return
    if not employ(empig_value):
        messagebox.showerror("Missing EmployID", "EmployID is necessary and must be less than 8 characters.")
        return

    if not validate_email(email_value):
        messagebox.showerror("Invalid Email", "Please enter a valid email address.")
        return

    if not phone_num(phone_value):
        messagebox.showerror("Invalid Phone Number", "Please enter a valid phone number.")
        return

    if not department(dept_value):
        messagebox.showerror("Department is Invalid", "Department must be at least 4 characters long.")
        return

    if not access_value:
        messagebox.showerror("Empty Access Value", "Fill access value.")
        return

    if not validate_password(password_value):
        messagebox.showerror(
            "Weak Password",
            "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character."
        )
        return

    if not age_value:
        messagebox.showerror("Not Selected Age", "Please select your age.")
        return

    if role_value == role_options[0]:
        messagebox.showerror("Fill Role", "Select your role.")
        return

    if sex_value == sex_option[0]:
        messagebox.showerror("Sex Not Selected", "Please select your sex.")
        return

    if country_value == country_options[0]:
        messagebox.showerror("Country Not Selected", "Please select your country.")
        return

    hashed_password = hash_password(password_value)
    md_passwords = md_password(password_value)

    K = Fernet.generate_key()

    results = (
        f"Name: {name_value}\n"
        f"LName: {lname_value}\n"
        f"EmployID: {empig_value}\n"
        f"Email: {email_value}\n"
        f"Phone: {phone_value}\n"
        f"Department: {dept_value}\n"
        f"Role: {role_value}\n"
        f"Access Level: {access_value}\n"
        f"Age: {age_value}\n"
        f"SHA-256 Hashed Password: {hashed_password}\n"
        f"MD5 Password: {md_passwords}\n"
        f"Encrypted Password: {Fernet(K).encrypt(password_value.encode())}\n"
        f"Country: {country_value}\n"
        f"Sex: {sex_value}"
    )

    results_label.config(text=results)

    messagebox.showinfo("Success", "Data saved successfully!")

def Clear():
    nameent.delete(0, END)
    lnameent.delete(0, END)
    empmeent.delete(0, END)
    emmeent.delete(0, END)
    phonent.delete(0, END)
    depent.delete(0, END)
    acessent.delete(0, END)
    passent.delete(0, END)

    role_var.set(role_options[0])
    country_var.set(country_options[0])
    sex_var.set(sex_option[0])
    entr.set(18)

    results_label.config(text="")

def toggle_left_frame():
    global left_visible
    if left_visible:
        left_frame.pack_forget()
        left_visible = False
        toggle_btn.config(text="Show Menu")
    else:
        left_frame.pack(side=LEFT, fill=Y)
        left_visible = True
        toggle_btn.config(text="Hide Menu")

def focus_fname(): nameent.focus_set()
def focus_lname(): lnameent.focus_set()
def focus_password(): passent.focus_set()
def focus_empId(): empmeent.focus_set()
def focus_email(): emmeent.focus_set()
def focus_phone(): phonent.focus_set()
def focus_dept(): depent.focus_set()
def focus_access(): acessent.focus_set()
def exit_app(): window.quit()
def open(): window.__new__()

window = Tk()
window.title("User Interface with Vertically Divided Right Frame")
window.geometry("900x1000")
window.configure(bg="#f0f4f8")

mymenu = Menu(window)
window.config(menu=mymenu)
file_menu = Menu(mymenu)
mymenu.add_cascade(menu=file_menu, label='File')
file_menu.add_command(label='Open', command=open)
file_menu.add_separator()
file_menu.add_command(label='Create')
file_menu.add_command(label='Open')
file_menu.add_command(label='Exit', command=exit_app)

window_menu = Menu(mymenu)
mymenu.add_cascade(menu=window_menu, label='Window')
window_menu.add_command(label='Layout')
window_menu.add_separator()
window_menu.add_command(label="Active layout")

Navigate_menu = Menu(mymenu)
mymenu.add_cascade(menu=Navigate_menu, label='Navigate')
Navigate_menu.add_command(label='<--Back')
Navigate_menu.add_separator()
Navigate_menu.add_command(label='Search')

Run_menu = Menu(mymenu)
mymenu.add_cascade(menu=Run_menu, label='Run')
Run_menu.add_command(label='Compile and Run')
Run_menu.add_separator()
Run_menu.add_command(label='Debug')

left_visible = True
left_frame = Frame(window, bg="#ffd2df", width=300)
left_frame.pack(side=LEFT, fill=Y)

toggle_btn = Button(left_frame, text="Hide Menu", command=toggle_left_frame, font=("Cambria", 14, "bold"),
                    bg="#00ff00", fg="white", relief=FLAT)
toggle_btn.pack(pady=15, padx=10)

nav_label = Label(left_frame, text="Registration Field", font=("Cambria", 20, "bold"), bg="#ffff00", fg="#2d3436")
nav_label.pack(pady=(10, 20))

options_mb = Menubutton(left_frame, text="Options ▼", font=("Cambria", 16, "bold"), bg="#ff0000", fg="white",
                        relief=FLAT, activebackground="#0984e3", activeforeground="white", width=15)
options_mb.menu = Menu(options_mb, tearoff=0, font=("Cambria", 14))
options_mb["menu"] = options_mb.menu
options_mb.menu.add_command(label="Option 1 - FName", command=focus_fname)
options_mb.menu.add_command(label="Option 2 - LName", command=focus_lname)
options_mb.menu.add_command(label="Option 3 - EmployID", command=focus_empId)
options_mb.menu.add_command(label="Option 4 - Email", command=focus_email)
options_mb.menu.add_command(label="Option 5 - Phone", command=focus_phone)
options_mb.menu.add_command(label="Option 6 - Department", command=focus_dept)
options_mb.menu.add_command(label="Option 8 - AccessLevel", command=focus_access)
options_mb.menu.add_command(label="Option 9 - Password", command=focus_password)
options_mb.pack(pady=5, padx=10)

right_frame = Frame(window, bg="#5f00f5")
right_frame.pack(side=RIGHT, fill=BOTH, expand=True)

title_label = Label(right_frame, text="User Interface", font=("Cambria", 28, "italic bold"), bg="#fff500", fg="#2c3e50")
title_label.grid(row=0, column=0, columnspan=2, sticky=NSEW, pady=10, padx=10)

# Configure grid for right_frame with 2 rows and 1 column:
right_frame.grid_rowconfigure(1, weight=3)  # form frame heavier
right_frame.grid_rowconfigure(2, weight=2)  # results frame lighter but visible
right_frame.grid_columnconfigure(0, weight=1)

# Top frame for form inputs
form_frame = Frame(right_frame, bg="#f0f4f8", bd=1, relief=SOLID)
form_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 5))

# Bottom frame for results output
results_frame = Frame(right_frame, bg="#d1d8e0", bd=2, relief=GROOVE)
results_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(5, 10))

common_font = ("Cambria", 20, "italic")
lbl_fg = "#0000ff"
entry_bg = "white"
entry_fg = "#0000ff"

def create_label(frame, text):
    return Label(frame, text=text, font=common_font, fg=lbl_fg, bg=form_frame.cget("bg"))

def create_entry(frame, width=25):
    ent = Entry(frame, font=common_font, bg=entry_bg, fg=entry_fg, relief=SOLID, bd=2, width=width)
    return ent

create_label(form_frame, "FName:").grid(row=0, column=0, sticky=W, pady=3, padx=5)
nameent = create_entry(form_frame)
nameent.grid(row=0, column=1, sticky=W, pady=3)

create_label(form_frame, "LName:").grid(row=1, column=0, sticky=W, pady=3, padx=5)
lnameent = create_entry(form_frame)
lnameent.grid(row=1, column=1, sticky=W, pady=3)

create_label(form_frame, "EmployID:").grid(row=2, column=0, sticky=W, pady=3, padx=5)
empmeent = create_entry(form_frame)
empmeent.grid(row=2, column=1, sticky=W, pady=3)

create_label(form_frame, "Email:").grid(row=3, column=0, sticky=W, pady=3, padx=5)
emmeent = create_entry(form_frame)
emmeent.grid(row=3, column=1, sticky=W, pady=3)

create_label(form_frame, "Phone:").grid(row=4, column=0, sticky=W, pady=3, padx=5)
phonent = create_entry(form_frame)
phonent.grid(row=4, column=1, sticky=W, pady=3)

create_label(form_frame, "Department:").grid(row=5, column=0, sticky=W, pady=3, padx=5)
depent = create_entry(form_frame)
depent.grid(row=5, column=1, sticky=W, pady=3)

create_label(form_frame, "AccessLevel:").grid(row=6, column=0, sticky=W, pady=3, padx=5)
acessent = create_entry(form_frame)
acessent.grid(row=6, column=1, sticky=W, pady=3)

create_label(form_frame, "Password:").grid(row=7, column=0, sticky=W, pady=3, padx=5)
passent = Entry(form_frame, font=common_font, bg=entry_bg, fg=entry_fg, relief=SOLID, bd=2, width=25, show='*')
passent.grid(row=7, column=1, sticky=W, pady=3)

create_label(form_frame, "Age:").grid(row=8, column=0, sticky=W, pady=3, padx=5)
entr = Scale(form_frame, from_=18, to=75, orient=HORIZONTAL, length=150, bg=form_frame.cget("bg"), fg=lbl_fg,
             troughcolor="#bdc3c7", highlightthickness=0)
entr.grid(row=8, column=1, sticky=W, pady=3)
entr.set(18)

create_label(form_frame, "Role:").grid(row=9, column=0, sticky=W, pady=3, padx=5)
role_options = ["Select role", "Student", "Teacher"]
role_var = StringVar(value=role_options[0])
role_menu = OptionMenu(form_frame, role_var, *role_options)
role_menu.config(font=common_font, bg="white", fg=entry_fg, relief=SOLID, bd=2)
role_menu.grid(row=9, column=1, sticky=W, pady=3)

create_label(form_frame, "Country:").grid(row=10, column=0, sticky=W, pady=3, padx=5)
country_options = ["Select Country", "Ethiopia", "Eritrea", "Djibouti", "Somalia", "Kenya"]
country_var = StringVar(value=country_options[0])
country_menu = OptionMenu(form_frame, country_var, *country_options)
country_menu.config(font=common_font, bg="white", fg=entry_fg, relief=SOLID, bd=2)
country_menu.grid(row=10, column=1, sticky=W, pady=3)

create_label(form_frame, "Sex:").grid(row=11, column=0, sticky=W, pady=3, padx=5)
sex_option = ["Sex", "M", "F"]
sex_var = StringVar(value=sex_option[0])
sex_menu = OptionMenu(form_frame, sex_var, *sex_option)
sex_menu.config(font=common_font, bg="white", fg=entry_fg, relief=SOLID, bd=2)
sex_menu.grid(row=11, column=1, sticky=W, pady=3)

btn_frame = Frame(form_frame, bg=form_frame.cget("bg"))
btn_frame.grid(row=12, column=0, columnspan=2, pady=15)

clear_btn = Button(btn_frame, text="Clear", font=("Cambria", 18, "bold"), bg="#2980b9", fg="white", relief=FLAT, command=Clear)
clear_btn.pack(side=LEFT, padx=10)

save_btn = Button(btn_frame, text="Save", font=("Cambria", 18, "bold"), bg="#27ae60", fg="white", relief=FLAT, command=Save)
save_btn.pack(side=RIGHT, padx=10)

# Results label with wrap and anchor top-left inside results_frame
results_label = Label(results_frame, text="", font=("Cambria", 16), bg=results_frame.cget("bg"), fg="#2c3e50",
                      justify=LEFT, anchor="nw", wraplength=800)
results_label.pack(fill=BOTH, expand=True, padx=10, pady=10)

window.mainloop()


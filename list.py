from tkinter import *
from tkinter import messagebox
import hashlib
import re

def hash_password(password):
    # Hash the password using SHA-256
    sha_signature = hashlib.sha256(password.encode()).hexdigest()
    return sha_signature

def validate_email(email):
    # Simple regex for validating an email
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_password(password):
    # Password must be at least 8 characters, contain uppercase, lowercase, digit and special character
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

    # Validate first name
    if not name_value:
        messagebox.showerror("Missing First Name", "First Name is required.")
        return
    if not lname_value:
        messagebox.showerror("Missing Last name Name", "Last Name is required.")
        return
        # Check if sex selected
    if not sex_value:
        messagebox.showerror("Sex Not Selected", "Please select your sex.")
        return
        
        # Validate password strength
    if not validate_password(password_value):
        messagebox.showerror(
            "Weak Password",
            "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character."
        )
        return

    # Validate email
    if not validate_email(email_value):
        messagebox.showerror("Invalid Email", "Please enter a valid email address.")
        return

    # Check if country selected
    if country_value == country_options[0]:
        messagebox.showerror("Country Not Selected", "Please select your country.")
        return


    # Hash the password
    hashed_password = hash_password(password_value)

    # Print the values (you can replace this with saving to a file or database)
    print(f"Name: {name_value}, LName: {lname_value}, Age: {age_value}, "
          f"Hashed Password: {hashed_password}, Country: {country_value}, "
          f"Email: {email_value}, Sex: {sex_value}")

    messagebox.showinfo("Success", "Data saved successfully!")

def Clear():
    nameent.delete(0, END)
    lnameent.delete(0, END)
    emmeent.delete(0, END)
    country_var.set(country_options[0])  # Reset to first option
    entr.set(18)  # Reset to minimum age
    passent.delete(0, END)
    sex_var.set(None)  # Reset radio button selection

window = Tk()
mymenu=Menu(window)
window.config(menu =mymenu)
file_menu =Menu(mymenu)

mymenu.add_cascade(menu=file_menu,label='File')
file_menu.add_command(label='Open')
file_menu.add_separator()
file_menu.add_command(label='Create')
file_menu.add_command(label='Open')
file_menu.add_command(label="Exit")

window_menu =Menu(mymenu)
mymenu.add_cascade(menu=window_menu,label ='Window')
window_menu.add_command(label='Layout')
window_menu.add_separator()
window_menu.add_command(label="Active layout")

Navigate_menu=Menu(mymenu)
mymenu.add_cascade(menu=Navigate_menu,label='Navigate')
Navigate_menu.add_command(label='<--Back')
Navigate_menu.add_separator()
Navigate_menu.add_command(label='search')

Run_menu=Menu(mymenu)
mymenu.add_cascade(menu=Run_menu,label='Run')
Run_menu.add_command(label='compile and run')
Run_menu.add_separator()
Run_menu.add_command(label='de_bug')

window.geometry('700x900')
window.title("User Interface")
window.configure(bg="#f0f4f8")  # Light background color for modern look

# Define common font for consistency
common_font = ("Cambria", 20, "italic")

# Title Label
title_label = Label(window, text="User Interface", font=("Cambria", 28, "italic bold"), bg="#f0f4f8", fg="#2c3e50")
title_label.place(x=100, y=30)

# Labels and Entries with consistent styling
lbl_fg = "#34495e"
entry_bg = "white"
entry_fg = "#2c3e50"

def create_label(text, x, y):
    return Label(window, text=text, font=common_font, fg=lbl_fg, bg="#f0f4f8")

def create_entry(x, y, width=25):
    ent = Entry(window, font=common_font, bg=entry_bg, fg=entry_fg, relief=SOLID, bd=2, width=width)
    ent.place(x=x, y=y)
    return ent

# First Name
create_label("FName:", 10, 100).place(x=10, y=100)
nameent = create_entry(140, 100)

# Last Name
create_label("LName:", 10, 160).place(x=10, y=160)
lnameent = create_entry(140, 160)

# Age
create_label("Age:", 10, 220).place(x=10, y=220)
entr = Scale(window, from_=18, to=75, orient=HORIZONTAL, length=150, bg="#f0f4f8", fg=lbl_fg, troughcolor="#bdc3c7", highlightthickness=0)
entr.place(x=140, y=220)
entr.set(18)

# Password
create_label("Password:", 10, 300).place(x=10, y=300)
passent = Entry(window, font=common_font, bg=entry_bg, fg=entry_fg, relief=SOLID, bd=2, width=25, show='.')
passent.place(x=160, y=300)

# Email
create_label("Email:", 10, 360).place(x=10, y=360)
emmeent = create_entry(140, 360)

# Country Dropdown
create_label("Country:", 10, 420).place(x=10, y=420)
country_options = ["Select Country", "Ethiopia", "Ertra", "Djibuti", "Somalia", "Kenya"]
country_var = StringVar(value=country_options[0])
country_menu = OptionMenu(window, country_var, *country_options)
country_menu.config(font=common_font, bg="white", fg=entry_fg, relief=SOLID, bd=2)
country_menu.place(x=160, y=420, width=300)

# Sex Radio Buttons
create_label("Sex:", 10, 480).place(x=10, y=480)
sex_var = StringVar()
male_rb = Radiobutton(window, text="Male", variable=sex_var, value="Male", font=common_font, bg="#f0f4f8", fg=lbl_fg, activebackground="#f0f4f8", activeforeground="#f0f4f8", selectcolor="#f1f0f1")
male_rb.place(x=160, y=480)
female_rb = Radiobutton(window, text="Female", variable=sex_var, value="Female", font=common_font, bg="#f0f4f8", fg=lbl_fg, activebackground="#f0f4f8", activeforeground="#f0f4f8", selectcolor="#f1f0f1")
female_rb.place(x=280, y=480)

# Buttons Style
btn_bg = "#2980b9"
btn_fg = "white"
btn_font = ("Cambria", 22, "bold")

clear_btn = Button(window, text="Clear", font=btn_font, bg=btn_bg, fg=btn_fg, activebackground="#3498db", activeforeground="white", relief=FLAT, command=Clear)
clear_btn.place(x=300, y=580, width=140, height=50)

save_btn = Button(window, text="Save", font=btn_font, bg="#27ae60", fg=btn_fg, activebackground="#2ecc71", activeforeground="white", relief=FLAT, command=Save)
save_btn.place(x=120, y=580, width=140, height=50)

window.mainloop()


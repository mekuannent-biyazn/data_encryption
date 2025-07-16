from tkinter import *
import hashlib


def hash_password(password):
    # Hash the password using SHA-256
    sha_signature = hashlib.sha256(password.encode()).hexdigest()
    return sha_signature


def Save():
    name_value = nameent.get()
    lname_value=lnameent.get()
    age_value = entr.get()
    password_value = passent.get()
    country_value=countryent.get()
    email_value=emmeent.get()
    # Hash the password
    hashed_password = hash_password(password_value)

    # Print the values (you can replace this with saving to a file or database)
    print(f"Name: {name_value}, Age: {age_value}, Hashed Password: {hashed_password} , County: {country_value}"
          f"Lname: {lname_value} ,Email: {email_value}")


def Clear():
    nameent.delete(0, END)
    lnameent.delete(0,END)
    emmeent.delete(0,END)
    countryent.delete(0,END)
    entr.set(0)
    passent.delete(0, END)


window=Tk()
window.geometry('700x900')
window.title("User interface")
intr=Label(text="user inter face",font=("cambria",25, "italic"))
intr.place(x=50,y=50)
name=Label(text="FName:",font=("cambria",25, "italic"))
name.place(x=10,y=100)
nameent=Entry(font=("cambria",25, "italic"))
nameent.place(x=117,y=100)

lname=Label(text="LName:",font=("cambria",25, "italic"))
lname.place(x=10,y=150)
lnameent=Entry(font=("cambria",25, "italic"))
lnameent.place(x=117,y=150)

age=Label(text="Age:",font=("cambria",25, "italic"))
age.place(x=10,y=200)
entr=Scale(from_=70,to=18)
entr.place(x=75,y=200)

passw=Label(text="Password:",font=("cambria",25, "italic"))
passw.place(x=10,y=300)
passent=Entry(font=("cambria",25, "italic"),show='*')
passent.place(x=155,y=300)

email=Label(text="Email:",font=("cambria",25, "italic"))
email.place(x=10,y=350)
emmeent=Entry(font=("cambria",25, "italic"))
emmeent.place(x=110,y=350)

country=Label(text="Country:",font=("cambria",25, "italic"))
country.place(x=10,y=400)
countryent=Entry(font=("cambria",25, "italic"))
countryent.place(x=110,y=400)

sex=Label(text="Sex:",font=("cambria",25, "italic"))
sex.place(x=10,y=500)
sexent=Radiobutton


clear=Button(text="Clear",font=("cambria",25, "italic"),command=Clear)
clear.place(x=300,y=500)

save=Button(text="Save",font=("cambria",25, "italic"),command=Save)
save.place(x=120,y=500)
window.mainloop()

from cryptography.fernet import Fernet
import hashlib
from tkinter import *

from list import save_btn
from mekurya import clear

with open('tex.txt','rb') as mm:
    mn=mm.read()
    key=Fernet.generate_key()
    print(Fernet(key).encrypt(mn))

    md5=hashlib.md5(mn).hexdigest()
    print(md5)

def savef():
    key=Fernet.generate_key()
    print(f"name encrypted by key : {Fernet(key).encrypt(name_entry.get().encode())},"
          f"name encrypyted by sha224: {hashlib.sha224(name_entry.get().encode()).hexdigest()}")
    print(f"password encrypted by key : {Fernet(key).encrypt(pass_entry.get().encode())},"
          f"password encrypyted by sha512: {hashlib.sha512(pass_entry.get().encode()).hexdigest()}")
def clear():
    name_entry.delete(0,END)
    pass_entry.delete(0,END)

win=Tk()
mymenu=Menu(win)
win.config(menu =mymenu)
file_menu =Menu(mymenu)

mymenu.add_cascade(menu=file_menu,label='File')
file_menu.add_command(label='Open')
file_menu.add_separator()
file_menu.add_command(label='Create')

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
win.geometry("700x500")
win.title("meku interface")
fontu=("Cambria",25,"italic")
Label(text="Name",font=fontu).place(x=10,y=10)
name_entry=Entry(font=fontu)
name_entry.place(x=150,y=10)

Label(text="password",font=fontu).place(x=10,y=60)
pass_entry=Entry(font=fontu)
pass_entry.place(x=150,y=60)

Button(text="save",font=("Cambria",25,"italic"),command=savef).place(x=100,y=120)
Button(text="clear",font=("Cambria",25,"italic"),command=clear).place(x=220,y=120)

win.mainloop()

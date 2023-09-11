from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)
def save_and_encrypt():
   title= title_entry.get()
   message= text_input.get("1.0", END)
   master= masterKey_input.get()

   if len(title)==0 or len(message) == 0 or len(master) == 0:
      messagebox.showinfo(title="Error!", message="Please enter all info.")

   else:
      #encryption
      message_encrypt= encode(master,message)
      try:
         with open("mysecret.txt","a") as data_file:
            data_file.write(f"\n{title}\n{message_encrypt}")
      except FileNotFoundError:
         with open("mysecret.txt","w") as data_file:
            data_file.write(f"\n{title}\n{message_encrypt}")
      finally:
         title_entry.delete(0,END)
         text_input.delete("1.0",END)
         masterKey_input.delete(0,END)

def decrypt_note():
    message_encrypt= text_input.get("1.0",END)
    master= masterKey_input.get()

    if len(message_encrypt)==0 or len(master) == 0:
        messagebox.showinfo(title="Error", message="Please enter all info.")
    else:
        try:
            decrypt_message= decode(master, message_encrypt)
            text_input.delete("1.0",END)
            text_input.insert("1.0", decrypt_message)
        except:
            messagebox.showinfo(title="Error", message="Please enter encrypted text!")





FONT=("Verdena",20,"normal")
window= Tk()
window.title("Secret Notes")
window.minsize(width=400, height=600)
window.config(padx=20, pady=20)
photo= PhotoImage(file="topsecret.png")
photo.label= Label(image=photo)
photo.label.pack()

#canvas= tkinter.Canvas(width=200, height=200)
#canvas.create_image(100,100, image=photo)
#canvas.pack()


title_Label=Label(text="Enter your title", font=FONT)
title_Label.pack()

title_entry = Entry(width=30)
title_entry.pack()

text_Label= Label(text="Enter your secret", padx=0, pady=5, font=FONT)
text_Label.pack()

text_input= Text(width=30, height=20)
text_input.pack()

masterKey_Label= Label(text="Enter master key", padx=0, pady=5, font=FONT)
masterKey_Label.pack()

masterKey_input= Entry(width=30)
masterKey_input.pack()

my_button = Button(text="Save & Encrypt", command=save_and_encrypt)

my_button.pack()

my_button1= Button(text="Decrypt", command=decrypt_note)
my_button1.pack()

decrypt_note()
window.mainloop()

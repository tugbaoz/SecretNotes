from tkinter import *
from PIL import ImageTk, Image
import base64
from tkinter import messagebox

window= Tk()
window.title("Secret Notes")
window.minsize(width=500, height=650)

frame= Frame(window, width=30, height=30, padx=20, pady=20)
frame.pack()

image= Image.open('image.jpg')
new_image= image.resize((100,100))
new_image.save('new_image.jpg')

path= 'new_image.jpg'

img= ImageTk.PhotoImage(Image.open(path))

panel= Label(frame, image=img)
panel.pack()

title_label= Label(text="Enter your title")
title_label.config(padx=5, pady=5)
title_label.pack()

title_entry= Entry(width=30)
title_entry.pack()

secret_label= Label(text="Enter your secret")
secret_label.config(padx=5, pady=5)
secret_label.pack()

text= Text(width=30, height=20,padx=5, pady=5)
text.pack()

master_key_label= Label(text="Enter master key")
master_key_label.config(padx=5, pady=5)
master_key_label.pack()

master_key_entry= Entry(width=30)
master_key_entry.pack()


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
    my_title= title_entry.get()
    message= text.get("1.0", END)
    master_key= master_key_entry.get()

    if len(my_title) == 0 or len(message) == 0 or len(master_key) ==0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        message_encrypted= encode(master_key, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{my_title}\n{message_encrypted}")

        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{my_title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            master_key_entry.delete(0, END)
            text.delete("1.0", END)


def decryption():
    message_encrypted= text.get("1.0", END)
    master_key = master_key_entry.get()
    if len(message_encrypted) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message= decode(master_key, message_encrypted)
            text.delete("1.0", END)
            text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")

button_1 = Button(text="Save & Encrypt", command=save_and_encrypt)
button_1.config(pady=5, padx=5)
button_1.pack()

button_2= Button(text="Decrypt", command=decryption)
button_2.config(padx=5, pady=5)
button_2.pack()

window.mainloop()

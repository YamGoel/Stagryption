from tkinter import *
import tkinter as tk
# import tkinter.filedialog
from tkinter import messagebox
from PIL import ImageTk
from PIL import Image
from io import BytesIO
import  os

class DataEncrypt:
    def main(self, root):
        root.title('Steganography')
        root.geometry('800x500') 
        # root.config(bg = '#e3f4f1')
        frame = Frame(root)
        frame.grid()

        title = Label(frame,text='Select the job')
        title.config(font=('Times new roman',25, 'bold'))
        # title.config(bg = '#e3f4f1')
        title.grid(row=1)
        title.grid(pady=20)
        title.grid(padx=300)

        encrypt = Button(frame, text="Encryption", width=10, height=2, command = lambda :self.encryption(frame))
        encrypt.config(font=('Helvetica',14))
        encrypt.grid(row=2)
        encrypt.grid(padx = 100)
        decrypt = Button(frame, text="Decryption", width=10, height=2, command = lambda :self.decryption(frame))
        decrypt.config(font=('Helvetica',14))
        decrypt.grid(padx = 200)
        decrypt.grid(row=3)
    
    def encryption(self,F):
        F.destroy()
        F2 = Frame(root)
        F2title = Label(text="Encryption")
        F2title.grid(row=1)
        textEnc = Button(text="Text Encryption",command = lambda :self.encryptText(F2))
        textEnc.grid(row=2)
        audioEnc = Button(text="Audio Encryption",command = lambda :self.encryptAudio(F2))
        audioEnc.grid(row=3)
        imageEnc = Button(text="Image Encryption",command = lambda :self.encryptImage(F2))
        imageEnc.grid(row=4)
        F2.grid()

    def decryption(self,F):
        F.destroy()
        F3 = Frame(root)
        F3.grid()

    def encryptText(self, F2):
        F2.destroy()
        F2_1 = Frame(root)
        F2_1title = Label(text="Text Encryption")
        F2_1title.grid(row=1)
        text = Text(width=80, height=5, padx=100)
        text.grid()
        F2_1submit = Button(text='Submit',command = lambda :self.encrypted(F2_1))
        F2_1submit.grid()
        F2_1.grid()

    def encryptAudio(self, F2):
        F2.destroy()
        F2_2 = Frame(root)
        F2_2title = Label(text="Audio Encryption")
        F2_2title.grid(row=1)
        F2_2submit = Button(text='Submit',command = lambda :self.encrypted(F2_2))
        F2_2submit.grid()
        F2_2.grid()

    def encryptImage(self, F2):
        F2.destroy()
        F2_3 = Frame(root)
        F2_3title = Label(text="Image Encryption")
        F2_3title.grid(row=1)
        F2_3submit = Button(text='Submit',command = lambda :self.encrypted(F2_3))
        F2_3submit.grid()
        F2_3.grid()

    def encrypted(self, F2_0):
        F2_0.destroy()
        F4 = Frame(root)
        F2_3title = Label(text="Encrypted Text")
        F2_3title.grid(row=1)
        F4.grid()

root = tk.Tk()
o = DataEncrypt()
o.main(root)
root.mainloop()

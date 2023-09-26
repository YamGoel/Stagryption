import tkinter as tk
import json
from tkinter import filedialog
from tkinter import messagebox
from tkinter import *
from PIL import ImageTk
import os
import PIL.Image
from io import BytesIO
from Cryptodome.Cipher import ChaCha20
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import base64
import image
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class NIS_Project:
    key = b'\x00' * 32

    def chacha20_encrypt_image(input_image_path, output_image_path):
        salt = b'\x00' * 16 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(NIS_Project.key)

        nonce = b'\x00' * 16 

        with open(input_image_path, 'rb') as file:
            image_data = file.read()

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(image_data) + encryptor.finalize()

        with open(output_image_path, 'wb') as file:
            file.write(ciphertext)
        return ciphertext

    def chacha20_decrypt_image():
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(NIS_Project.key)

        nonce = b'\x00' * 16

        with open("encrypted_image.jpg", 'rb') as file:
            ciphertext = file.read()

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open("decrypted_image.jpg", 'wb') as file:
            file.write(plaintext)

    def chacha20_encrypt_audio(input_audio_path):
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(NIS_Project.key)

        nonce = b'\x00' * 16

        with open(input_audio_path, 'rb') as file:
            audio_data = file.read()

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(audio_data) + encryptor.finalize()

        with open("encrypted_audio.m4a", 'wb') as file:
            file.write(ciphertext)
        return ciphertext

    def chacha20_decrypt_audio():

        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(NIS_Project.key)
        nonce = b'\x00' * 16

        with open("encrypted_audio.m4a", 'rb') as file:
            ciphertext = file.read()

        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open("decrypted_audio.m4a", 'wb') as file:
            file.write(plaintext)

    def main(self, root):

        ########### ROOT FRAME ##########

        root.title("Steganography")
        root.geometry("500x300")

        roottitle = tk.Label(root, text="Select:")
        roottitle.config(font=('Times new roman', 25, 'bold'))
        roottitle.pack(padx=200, pady=30)

        enc_button = tk.Button(root, text="Encryption", command=lambda: new_encryption_frame(root))
        enc_button.config(font=('Times new roman', 20, 'bold'))
        enc_button.pack(padx=20, pady=20)

        dec_button = tk.Button(root, text="Decryption", command=lambda: new_decryption_frame(root))
        dec_button.config(font=('Times new roman', 20, 'bold'))
        dec_button.pack(padx=20, pady=20)

        def new_encryption_frame(root):
            root.destroy()
            encryption_frame = tk.Tk()
            encryption_frame.title("Encryption")
            encryption_frame.geometry("500x400")

            enctitle = tk.Label(encryption_frame, text="Select:")
            enctitle.config(font=('Times new roman', 25, 'bold'))
            enctitle.pack(padx=200, pady=30)

            text_button = tk.Button(encryption_frame, text="Text", command=lambda: new_text_frame(encryption_frame))
            text_button.config(font=('Times new roman', 20, 'bold'))
            text_button.pack(padx=20, pady=20)

            ######### TEXT FRAME ############

            def new_text_frame(encryption_frame):
                encryption_frame.destroy()
                text_frame = tk.Tk()
                text_frame.title("Text")
                text_frame.geometry("500x400")

                texttitle = tk.Label(text_frame, text="Select:")
                texttitle.config(font=('Times new roman', 25, 'bold'))
                texttitle.pack(padx=200, pady=30)

                text_var = tk.StringVar()

                text_input = tk.Entry(text_frame, textvariable=text_var, width=60)
                text_input.config(font=('Times new roman', 10, 'bold'))
                text_input.pack()

                subText = tk.Button(text_frame, text="Submit", command=lambda: subText(text_frame))
                subText.config(font=('Times new roman', 10, 'bold'))
                subText.pack(padx=10, pady=10)

                def subText(text_frame):
                    textinp = text_input.get()
                    text = textinp.encode('utf-8')
                    if not text_input.get():
                        messagebox.showerror("Error","Please enter some text!")
                    else:
                        cipher = ChaCha20.new(key=NIS_Project.key)
                        ciphertext = cipher.encrypt(text)
                        nonce = b64encode(cipher.nonce).decode('utf-8')
                        enc_text = b64encode(ciphertext).decode('utf-8')
                        encrypted_data = tk.Tk()
                        encrypted_data.title("Encrypted Data")
                        encrypted_data.geometry("500x400")

                        enc_title = tk.Label(encrypted_data, text = "Encrypted Data")
                        enc_title.config(font=('Times new roman', 25, 'bold'))
                        enc_title.pack(padx=10, pady=30)
                        
                        encText = tk.Text(encrypted_data, width=80, height=10)
                        encText.config(font=('Times new roman', 11))
                        encText.insert(INSERT, enc_text)
                        encText.pack(padx=10, pady=10)
                        encText.configure(state='disabled')

                        stegButton = tk.Button(encrypted_data, text="Perform Steganography", command= lambda: NIS_Project.performSteganography(encrypted_data, enc_text+nonce))
                        stegButton.config(font=('Times new roman', 13, 'bold'))
                        stegButton.pack(padx=10,pady=10)

                        text_frame.destroy()


            audio_button = tk.Button(encryption_frame, text="Audio", command=lambda: new_audio_frame(encryption_frame))
            audio_button.config(font=('Times new roman', 20, 'bold'))
            audio_button.pack(padx=20, pady=20)

            ########### AUDIO FRAME ##########

            def new_audio_frame(encryption_frame):
                encryption_frame.destroy()
                audio_frame = tk.Tk()
                audio_frame.title("Text")
                audio_frame.geometry("500x400")

                audiotitle = tk.Label(audio_frame, text="Select Audio file:")
                audiotitle.config(font=('Times new roman', 25, 'bold'))
                audiotitle.pack(padx=50, pady=30)

                def open_audio():
                    the_file = filedialog.askopenfilename(  
                    title = "Select an Audio file : ",  
                    filetypes = [("mp3", "*.mp3"),('wav', '*.wav'),('m4a', '*.m4a')]  
                    )
                    enc_audio = NIS_Project.chacha20_encrypt_audio(the_file)
                    print("Audio encrypted successfully.")
                    subAudio = tk.Button(audio_frame, text="Submit", command=lambda: subAudio(audio_frame, enc_audio))
                    subAudio.config(font=('Times new roman', 10, 'bold'))
                    subAudio.pack(padx=10, pady=10)

                    def subAudio(audio_frame, encAudio):
                        audio_frame.destroy()
                        cipher = ChaCha20.new(key=NIS_Project.key)
                        ciphertext = cipher.encrypt(encAudio)
                        nonce = b64encode(cipher.nonce).decode('utf-8')
                        enc_audio = b64encode(ciphertext).decode('utf-8')
                        NIS_Project.performSteganography(audio_frame, enc_audio+nonce)


                audio = tk.Button(audio_frame, text="Select Audio", command=open_audio)
                audio.pack()

                def subAudio(text_frame):
                    enc_text = "Encrypted Text"
                    audio_frame.destroy()


            image_button = tk.Button(encryption_frame, text="Image", command=lambda: new_image_frame(encryption_frame))
            image_button.config(font=('Times new roman', 20, 'bold'))
            image_button.pack(padx=20, pady=20)

            ########### IMAGE FRAME ##########

            def new_image_frame(encryption_frame):
                encryption_frame.destroy()
                image_frame = tk.Tk()
                image_frame.title("Text")
                image_frame.geometry("500x400")

                imagetitle = tk.Label(image_frame, text="Select the image:")
                imagetitle.config(font=('Times new roman', 25, 'bold'))
                imagetitle.pack(padx=50, pady=30)

                def open_image():
                    the_file = filedialog.askopenfilename(  
                    title = "Select an Image file : ",  
                    filetypes = [('png', '*.png'),('jpeg', '*.jpeg'),('jpg', '*.jpg')]  
                    )
                    output_image_path = 'encrypted_image.jpg'
                    enc_image = NIS_Project.chacha20_encrypt_image(the_file, output_image_path)
                    print("Image encrypted successfully.")
                    subImage = tk.Button(image_frame, text="Submit", command=lambda: subImage(image_frame, enc_image))
                    subImage.config(font=('Times new roman', 10, 'bold'))
                    subImage.pack(padx=10, pady=10)

                    def subImage(image_frame, encImage):
                        image_frame.destroy()
                        cipher = ChaCha20.new(key=NIS_Project.key)
                        ciphertext = cipher.encrypt(encImage)
                        nonce = b64encode(cipher.nonce).decode('utf-8')
                        enc_image = b64encode(ciphertext).decode('utf-8')
                        NIS_Project.performSteganography(image_frame, enc_image+nonce)
                        
                        
                image = tk.Button(image_frame, text="Select Image", command=open_image)
                image.pack()

        ######### Decryption Frame #########

        def new_decryption_frame(root):
            root.destroy()
            decryption_frame = tk.Tk()
            decryption_frame.title("Decryption")
            decryption_frame.geometry("1000x800")

            dectitle = tk.Label(decryption_frame, text="Select:")
            dectitle.config(font=('Times new roman', 25, 'bold'))
            dectitle.pack(padx=50, pady=10)

            myStegFile = tk.filedialog.askopenfilename(filetypes = ([('png', '*.png'),('jpeg', '*.jpeg'),('jpg', '*.jpg'),('All Files', '*.*')]))
            if not myStegFile:
                messagebox.showerror("Error","You have selected nothing !")
            else:
                my_img = PIL.Image.open(myStegFile)
                new_image = my_img.resize((250,140))
                img = ImageTk.PhotoImage(new_image)
                stegtitle= tk.Label(decryption_frame,text='Selected Image')
                stegtitle.config(font=('Helvetica',14,'bold'))
                stegtitle.pack(pady=10)
                board = tk.Label(decryption_frame, image=img)
                board.image = img
                output_image_size = os.stat(myStegFile)
                o_image_w, o_image_h = my_img.size
                board.pack()
                hidden_data = NIS_Project.decode(my_img)
                hidden_label = tk.Label(decryption_frame, text='Hidden data is :')
                hidden_label.config(font=('Helvetica',12,'bold'))
                hidden_label.pack(padx=5,pady=5)

                encText = hidden_data[:-12]
                n = hidden_data[-12:]

                ciphertext = b64decode(encText)
                nonce = b64decode(n)

                cipher = ChaCha20.new(key=NIS_Project.key, nonce=nonce)
                plaintext = cipher.decrypt(ciphertext)

                enc_Text = tk.Text(decryption_frame, width=150, height=5)
                enc_Text.insert(INSERT, encText)
                enc_Text.configure(state='disabled')
                enc_Text.pack(pady=5)

                plain_label = tk.Label(decryption_frame, text='Plain data is :')
                plain_label.config(font=('Helvetica',12,'bold'))
                plain_label.pack(padx=5,pady=5)

                plain_Text = tk.Text(decryption_frame, width=150, height=5)
                plain_Text.insert(INSERT, plaintext)
                plain_Text.configure(state='disabled')
                plain_Text.pack(pady=5)

                decryptImageButton = tk.Button(decryption_frame, text="Decrypt Image", command=lambda: toImage(decryption_frame))
                decryptImageButton.pack(pady=5)

                def toImage(decryption_frame):
                    NIS_Project.chacha20_decrypt_image()
                    print("Image has been Decrypted")
                    decryption_frame.destroy()

                decryptAudioButton = tk.Button(decryption_frame, text="Decrypt Audio", command=lambda: toAudio(decryption_frame))
                decryptAudioButton.pack(pady=5)

                def toAudio(decryption_frame):
                    NIS_Project.chacha20_decrypt_audio()
                    print("Audio has been Decrypted")
                    decryption_frame.destroy()


    def decode(image):
        image_data = iter(image.getdata())
        data = ''

        while (True):
            pixels = [value for value in image_data.__next__()[:3] +
                      image_data.__next__()[:3] +
                      image_data.__next__()[:3]]
            binary_str = ''
            for i in pixels[:8]:
                if i % 2 == 0:
                    binary_str += '0'
                else:
                    binary_str += '1'

            data += chr(int(binary_str, 2))
            if pixels[-1] % 2 != 0:
                return data

    def performSteganography(encrypted_data, data): 
        steganography = tk.Tk()
        steganography.title("Steganography")
        steganography.geometry("500x600")
        myfile = tk.filedialog.askopenfilename(filetypes = ([('png', '*.png'),('jpeg', '*.jpeg'),('jpg', '*.jpg'),('All Files', '*.*')]))
        if not myfile:
            messagebox.showerror("Error","You have selected nothing !")
        else:
            my_img = PIL.Image.open(myfile)
            new_image = my_img.resize((300,200))
            img = ImageTk.PhotoImage(new_image)
            stegtitle= tk.Label(steganography,text='Selected Image')
            stegtitle.config(font=('Helvetica',14,'bold'))
            stegtitle.pack(padx=20,pady=20)
            board = tk.Label(steganography, image=img)
            board.image = img
            output_image_size = os.stat(myfile)
            o_image_w, o_image_h = my_img.size
            board.pack()
            steg_encode = tk.Button(steganography, text='Encode', command=lambda : NIS_Project.steg_enc_fun(data,my_img))
            steg_encode.config(font=('Helvetica',14))
            steg_encode.pack(padx=20, pady=20)

            home = tk.Button(steganography, text="Home", command=lambda:home(steganography))
            home.config(font=('Times new roman', 10, 'bold'))
            home.pack(padx=10, pady=10)

            def home(steganography):
                steganography.destroy()
                root = tk.Tk()
                obj = NIS_Project()
                obj.main(root)

    ############# Function to Generate data ##########

    def generate_Data(data):
        new_data = []

        for i in data:
            new_data.append(format(ord(i), '08b'))
        return new_data

    ######### Function to modify Pixels of Image ###########

    def modify_Pix(pix, data):
        dataList = NIS_Project.generate_Data(data)
        dataLen = len(dataList)
        imgData = iter(pix)
        for i in range(dataLen):
            # Extracting 3 pixels at a time
            pix = [value for value in imgData.__next__()[:3] +
                   imgData.__next__()[:3] +
                   imgData.__next__()[:3]]
            
            for j in range(0, 8):
                if (dataList[i][j] == '0') and (pix[j] % 2 != 0):
                    if (pix[j] % 2 != 0):
                        pix[j] -= 1

                elif (dataList[i][j] == '1') and (pix[j] % 2 == 0):
                    pix[j] -= 1
            
            if (i == dataLen - 1):
                if (pix[-1] % 2 == 0):
                    pix[-1] -= 1
            else:
                if (pix[-1] % 2 != 0):
                    pix[-1] -= 1

            pix = tuple(pix)
            yield pix[0:3]
            yield pix[3:6]
            yield pix[6:9]

    ######### Function to perform Steganography Encoding ########

    def encode_enc(newImg, data):
        w = newImg.size[0]
        (x, y) = (0, 0)

        for pixel in NIS_Project.modify_Pix(newImg.getdata(), data):

            # Putting modified pixels in the new image
            newImg.putpixel((x, y), pixel)
            if (x == w - 1):
                x = 0
                y += 1
            else:
                x += 1

    ######## Function to call Encryption Function #######
    
    def steg_enc_fun(data,myImg):
        if (len(data) == 0):
            messagebox.showinfo("Alert","There is no Data.")
        else:
            newImg = myImg.copy()
            NIS_Project.encode_enc(newImg, data)
            my_file = BytesIO()
            temp=os.path.splitext(os.path.basename(myImg.filename))[0]
            newImg.save(tk.filedialog.asksaveasfilename(initialfile=temp,filetypes = ([('png', '*.png')]),defaultextension=".png"))
            d_image_size = my_file.tell()
            d_image_w,d_image_h = newImg.size
            messagebox.showinfo("Success","Encoding Successful\nFile is saved in the same directory")

root = tk.Tk()
obj = NIS_Project()
obj.main(root)
root.mainloop()

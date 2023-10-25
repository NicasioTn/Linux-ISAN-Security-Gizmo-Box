import json
import os
import hashlib
import qrcode
import requests
import pyperclip
import configparser
from PyQt6.QtWidgets import QFileDialog, QDialog
from PyQt6.QtGui import QPixmap
from pathlib import Path

class MessageDigest(QDialog):

    path = ''
    algorithm = ''
    state_detect = 0
    state_line = False

    def __init__(self):
        #super(MessageDigest, self).__init__()
        super().__init__()

    def LoadAPIKey(self):
        # Fetch API Key from config file
        config = configparser.ConfigParser()
        configFilePath = f'{os.getcwd}/data/init.conf'
        config.read(configFilePath)
        if 'LineNotify' in config:
            line_api_key = config.get('LineNotify', 'line_api_key')
            self.lineEdit_tokenMSDigest.setText(line_api_key)
            # print(f'Line API Key: {line_api_key}')
        else:
            print('Section "LineNotify" does not exist in the config file.')
        return line_api_key

    def saveAPIKey(self, line_api_key):
        print(line_api_key)

        # save api key to file init.conf
        config = configparser.ConfigParser()
        configFilePath = f'{os.getcwd}/data/init.conf'
        config.read(configFilePath)
        if 'LineNotify' in config:
            config.set('LineNotify', 'line_api_key', str(line_api_key))
            print(f'Set API KEY: {line_api_key}')
        else:
            print('Section "LineNotify" does not exist in the config file.')

        with open(configFilePath, 'w') as configfile:
            config.write(configfile)
        
    def clear(self):
        self.lineEdit_MSdigest.setText('')
        self.label_QRCode.clear()
        self.dropdown_sha2.setCurrentIndex(0)
        self.dropdown_sha3.setCurrentIndex(0)
        self.label_lineAPIDigest.setVisible(False)
        self.lineEdit_tokenMSDigest.setVisible(False)
        self.btn_sendMSDigest.setVisible(False)
        self.btn_infoToken.setVisible(False)
        self.lineEdit_tokenMSDigest.setText('')
        self.lineEdit_outputTextMSDigest.setText('')
        self.lineEdit_outputTextMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid black;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
        self.lineEdit_outputTextMSDigest.setPlaceholderText('')
        self.label_type.setText('Type')
        self.btn_saveQR.setText('SAVE')
        MessageDigest.LoadAPIKey(self)
    
    def qrCodeGenerator(self, hash):
        if self.lineEdit_outputTextMSDigest == '': # check current text output is empty 
            print("Error: QR-Code is Not Generated")
            self.lineEdit_outputTextMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
            self.lineEdit_outputTextMSDigest.setPlaceholderText("Empty")
            return
        # Generate QR Code
        qr = qrcode.QRCode(
            version=1,
            box_size=10,
            border=5
        )
        qr.add_data(hash)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(f"{os.getcwd}/data/MessageDigest-QRCode.png")
        print("QR Code Generated")
        return img
        
    def ShowImage_QR(self):
        if self.lineEdit_outputTextMSDigest.text() == '':
            print("Error: QR-Code is Not Generated")
            self.lineEdit_outputTextMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
            self.lineEdit_outputTextMSDigest.setPlaceholderText("Empty")
            return
        imagePath = f"{os.getcwd}/data/MessageDigest-QRCode.png"
        pixmap = QPixmap(imagePath)
        pixmap = pixmap.scaledToWidth(200)
        pixmap = pixmap.scaledToHeight(200)
        self.label_QRCode.setPixmap(pixmap)

    def openFileDialog(self):
        path = MessageDigest.open_file_dialog(self)

        # try except to check if file exists
        try:
            if path.exists() == True: # check if file exists
                print(f"File exists at: {path.exists()}" + " ++")
        except AttributeError as e:
            print(f"Empty file or Not found")

        MessageDigest.setPath(self, path)
    
    def setPath(self, path):
        MessageDigest.path = path

    def getPath(self):
        return MessageDigest.path

    def showBtnLine(self, state):
        # Open File Line API Key
        if state == True:
            self.label_lineAPIDigest.setVisible(True)
            self.lineEdit_tokenMSDigest.setVisible(True)
            self.btn_sendMSDigest.setVisible(True)
            self.btn_infoToken.setVisible(True)
            MessageDigest.state_line = False
        else:
            self.label_lineAPIDigest.setVisible(False)
            self.lineEdit_tokenMSDigest.setVisible(False)
            self.btn_sendMSDigest.setVisible(False)
            self.btn_infoToken.setVisible(False)
            MessageDigest.state_line = True
    
    def open_file_dialog(self):
        filename, ok = QFileDialog.getOpenFileName(
            self,
            "Select a File", 
            os.getcwd(), 
            "All Files (*.*)" # filter file type text but can select all file
        )
        if filename:
            path = Path(filename)
            self.lineEdit_MSdigest.setText(str(path))
            if path.exists() != True: # check if file exists 
                print(f"File exists at: {path.exists()}")
            print(f"Get file at: {path}") 

            return path

    def checkFile_Text(self):
        if os.path.exists(self.lineEdit_MSdigest.text()) == True: # check if file exists
            print("File")
            MessageDigest.state_detect = 1
            self.btn_md5.clicked.connect(lambda: MessageDigest.fileExtract(self, "md5", MessageDigest.getPath(self)))
            self.btn_sha1.clicked.connect(lambda: MessageDigest.fileExtract(self, "sha1", MessageDigest.getPath(self)))
            self.dropdown_sha2.activated.connect(lambda: MessageDigest.fileExtract(self, "sha2_" + self.dropdown_sha2.currentText(), MessageDigest.getPath(self)))
            self.dropdown_sha3.activated.connect(lambda: MessageDigest.fileExtract(self, "sha3_" + self.dropdown_sha3.currentText(), MessageDigest.getPath(self)))
        else:
            MessageDigest.state_detect = 0
            print("Plaintext")
            self.btn_md5.clicked.connect(lambda: MessageDigest.hash(self, "md5"))
            self.btn_sha1.clicked.connect(lambda: MessageDigest.hash(self, "sha1"))
            self.dropdown_sha2.activated.connect(lambda: MessageDigest.getdropdown_sha2(self))
            self.dropdown_sha3.activated.connect(lambda: MessageDigest.getdropdown_sha3(self))

        # show Image QR Code
        self.btn_md5.clicked.connect(lambda: MessageDigest.ShowImage_QR(self))
        self.btn_sha1.clicked.connect(lambda: MessageDigest.ShowImage_QR(self))
        self.dropdown_sha2.activated.connect(lambda: MessageDigest.ShowImage_QR(self))
        self.dropdown_sha3.activated.connect(lambda: MessageDigest.ShowImage_QR(self))

    def getdropdown_sha2(self):
        MessageDigest.hash(self, "sha2_" + self.dropdown_sha2.currentText())
        MessageDigest.algorithm = 'SHA2-' + self.dropdown_sha2.currentText()
        self.dropdown_sha3.setCurrentIndex(0)

    def getdropdown_sha3(self):
        MessageDigest.hash(self, "sha3_" + self.dropdown_sha3.currentText())
        MessageDigest.algorithm = 'SHA3-' + self.dropdown_sha3.currentText()
        self.dropdown_sha2.setCurrentIndex(0)

    def hash(self, type):
        #print(self.dropdown_sha2.currentText())
        if type == "md5":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.md5(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'MD5'
            
        elif type == "sha1":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha1(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA-1'
            
        elif type == "sha2_224 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha224(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA2-224'
            
        elif type == "sha2_256 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha256(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA2-256'
            
        elif type == "sha2_384 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha384(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA2-384'
            
        elif type == "sha2_512 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha512(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA2-512'
            
        elif type == "sha3_224 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha3_224(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA3-224'
            
        elif type == "sha3_256 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha3_256(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA3-256'
            
        elif type == "sha3_384 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha3_384(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA3-384'
            
        elif type == "sha3_512 BIT":
            self.lineEdit_outputTextMSDigest.setText(MessageDigest.sha3_512(self, self.lineEdit_MSdigest.text())) \
                if self.lineEdit_MSdigest.text() != '' else self.lineEdit_outputTextMSDigest.setText('')
            self.algorithm = 'SHA3-512'
            

        self.label_type.setText(self.algorithm) if self.lineEdit_MSdigest.text() != '' else self.label_type.setText('Type')
        # reset copy button
        self.btn_copy.setText('Copy')


        
    def fileExtract(self, type, path):
        print(type)
        if type == "md5":
            MessageDigest.fileHash(self, "md5", path)
        elif type == "sha1":
            MessageDigest.fileHash(self, "sha1", path)
        elif type == "sha2_224 BIT":
            MessageDigest.fileHash(self, "sha224", path)
        elif type == "sha2_256 BIT":
            MessageDigest.fileHash(self, "sha256", path)
        elif type == "sha2_384 BIT":
            MessageDigest.fileHash(self, "sha384", path)
        elif type == "sha2_512 BIT":
            MessageDigest.fileHash(self, "sha512", path)
        elif type == "sha3_224 BIT":
            MessageDigest.fileHash(self, "sha3_224", path)
        elif type == "sha3_256 BIT":
            MessageDigest.fileHash(self, "sha3_256", path)
        elif type == "sha3_384 BIT":
            MessageDigest.fileHash(self, "sha3_384", path)
        elif type == "sha3_512 BIT":
            MessageDigest.fileHash(self, "sha3_512", path)

        # Show Image QR Code
        self.btn_md5.clicked.connect(lambda: MessageDigest.ShowImage_QR(self))
        self.btn_sha1.clicked.connect(lambda: MessageDigest.ShowImage_QR(self))
        self.dropdown_sha2.activated.connect(lambda: MessageDigest.ShowImage_QR(self))
        self.dropdown_sha3.activated.connect(lambda: MessageDigest.ShowImage_QR(self))
    
    # File Hashing -----------------------------------------------
    def fileHash(self, type, path):
        MessageDigest.LoadAPIKey(self)
        text_type = type
        if "_" in type:
            text_type = text_type.replace("_", " ")
        self.label_type.setText(text_type.upper())

        if type == "md5":
            init_hash = hashlib.md5()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}")
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha1":
            init_hash = hashlib.sha1()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}")
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha224":
            init_hash = hashlib.sha224()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}")
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha256":
            init_hash = hashlib.sha256()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}")
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha384":
            init_hash = hashlib.sha384()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}")
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha512":
            init_hash = hashlib.sha512()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}")
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha3_224":
            init_hash = hashlib.sha3_224()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}") 
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha3_256":
            init_hash = hashlib.sha3_256()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}") 
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha3_384":
            init_hash = hashlib.sha3_384()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}") 
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')

        elif type == "sha3_512":
            init_hash = hashlib.sha3_512()
            file = path
            BLOCK_SIZE = 65536 
            with open(file, 'rb') as f: 
                fb = f.read(BLOCK_SIZE) 
                while len(fb) > 0: 
                    init_hash.update(fb) 
                    fb = f.read(BLOCK_SIZE) 
            file_hashed =  init_hash.hexdigest()
            print (f"This is file hash {type}: {file_hashed}") 
            self.lineEdit_outputTextMSDigest.setText(f'{file_hashed}')
        
    def saveQRCode(self):
        if self.lineEdit_outputTextMSDigest.text() == '':
            print("Error: QR-Code is Not Generated")
            self.lineEdit_MSdigest.setStyleSheet("border: 1px solid red;")
            self.lineEdit_MSdigest.setPlaceholderText("Empty")
            return
        pathfile, ok = QFileDialog.getSaveFileName(
            self,
            "Save File",
            "MessageDigest-QRCode-" + self.algorithm + ".png",
            "Images (*.png *.jpg)")
        
        # Check if a filename was provided
        if pathfile: # show place to save
            print("Save at: ", pathfile)
            # Save QR-Code with pixmap at pathfile
            if not self.label_QRCode.pixmap().isNull():
                # Save the pixmap to the specified file path
                self.label_QRCode.pixmap().save(pathfile, 'PNG')
                # Set the text of the save button to "SAVED!" to indicate successful save
                self.btn_saveQR.setText("SAVED!")
            else:
                print("Error: QR-Code is Not Generated")
        else:
            print("Error: No file name specified")
    
    # Type of Hashing ------------------------------------------
    def md5(self, data):
        return hashlib.md5(data.encode('utf-8')).hexdigest()

    def sha1(self, data):
        return hashlib.sha1(data.encode('utf-8')).hexdigest()

    def sha224(self, data):
        return hashlib.sha224(data.encode('utf-8')).hexdigest()

    def sha256(self, data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def sha384(self, data):
        return hashlib.sha384(data.encode('utf-8')).hexdigest()

    def sha512(self, data):
        return hashlib.sha512(data.encode('utf-8')).hexdigest()

    def sha3_224(self, data):
        return hashlib.sha3_224(data.encode('utf-8')).hexdigest()

    def sha3_256(self, data):
        return hashlib.sha3_256(data.encode('utf-8')).hexdigest()

    def sha3_384(self, data):
        return hashlib.sha3_384(data.encode('utf-8')).hexdigest()

    def sha3_512(self, data):
        return hashlib.sha3_512(data.encode('utf-8')).hexdigest()
    
    def processLineKey(self):
        if self.lineEdit_MSdigest.text() == '':
            print("Data to send Empty")
            self.lineEdit_outputTextMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
            self.lineEdit_outputTextMSDigest.setPlaceholderText("Empty")
            return 
        type = self.label_type.text()
        message = self.lineEdit_outputTextMSDigest.text() + "\nHash Algorithms: " + type
        token = self.lineEdit_tokenMSDigest.text()
        try:
            if token != '':
                getQR = f"{os.getcwd}/data/MessageDigest-QRCode.png"
                url = "https://notify-api.line.me/api/notify"

                headers = {"Authorization": "Bearer " + token}
                payload = {"message": message}

                with open(getQR, "rb") as image_file:
                    files = {"imageFile": image_file}
                    response = requests.post(url, headers=headers, params=payload, files=files)
                
                if response.status_code == 200:
                    MessageDigest.saveAPIKey(self, self.lineEdit_LineAPISettings.text()) # save api key to file init.conf
                    print("Image sent successfully!")
                    self.lineEdit_tokenMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid green;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
                elif response.status_code == 400:
                    print("Bad request!")
                    self.lineEdit_tokenMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
                elif response.status_code == 401:
                    print("Invalid access token!")
                    self.lineEdit_tokenMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid Orange;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
                elif response.status_code == 500:
                    print("Server error!")
                    self.lineEdit_tokenMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid yellow;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
                else:
                    print("Process over time.")
                    self.lineEdit_tokenMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid gray;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
            else:
                self.lineEdit_tokenMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
        except UnicodeEncodeError as e:
            print("Cannot send message to LINE")
            
    def copyOutput(self):
        clipboard = self.lineEdit_outputTextMSDigest.text()
        # copy to clipboard
        if clipboard == '':
            self.lineEdit_outputTextMSDigest.setPlaceholderText("Empty")
            self.lineEdit_outputTextMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid red;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
        else:
            self.lineEdit_outputTextMSDigest.setStyleSheet('''QLineEdit {
  border: 1px solid green;
  color: rgba(40,43,61,255);
  border-radius: 5px;
}

QLineEdit:hover {
  border: 2px solid;
  border-color: rgba(0,143,255,255);
}
QLineEdit:focus {
  border: 1px solid;
  border-color: rgba(88,199,141,255);
}
''')
            self.btn_copy.setText("Copied!")
            pyperclip.copy(clipboard)
    
    def infoToken(self):
        # Open link to browser line notify
        import webbrowser
        webbrowser.open('https://notify-bot.line.me/doc/en/')
        

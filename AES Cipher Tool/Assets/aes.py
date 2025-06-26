from Cryptodome.Cipher import AES
import hashlib
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PyQt6.QtWidgets import QFileDialog, QApplication, QMessageBox
from PyQt6 import QtWidgets, uic ,QtCore, QtGui
import os, sys, json, struct, pathlib

class UIHandler(QtWidgets.QMainWindow) :
    def __init__(self, path) :
        super(UIHandler, self).__init__()
        ui_path = path
        uic.loadUi(ui_path,self)

        self.uierrDict={2103:"fileMiss",2104:"SavePthMiss",1098:"nonENC",3012:"keyErr",3013:"ivErr"}
        self.status = {"encr","decr"}

        self.file_path = None
        self.dir_path = None
        self.data = None

        


        # Tool Buttons
        self.buttonFileChoose = self.findChild(QtWidgets.QToolButton , "FileChooseBut")
        self.SavePathButton = self.findChild( QtWidgets.QToolButton , "SaveToolButton")
        
        # Line Edit
        self.filePathlnEdit = self.findChild(QtWidgets.QLineEdit , "FilePathLine")
        self.SavePathlnEdit = self.findChild(QtWidgets.QLineEdit , "SavePathLnEdit")
        self.aeskey = self.findChild(QtWidgets.QLineEdit, "AESKey")
        self.aesiv  = self.findChild(QtWidgets.QLineEdit, "AESiv")

        # Checkbox
        self.CheckSamePath = self.findChild(QtWidgets.QCheckBox, "SamePathCheck")

        # Push Buttons 
        self.helpButton = self.findChild(QtWidgets.QPushButton, "Help")
        self.aboutButton = self.findChild(QtWidgets.QPushButton, "About")
        self.donebutton = self.findChild(QtWidgets.QPushButton, "Done")

        self.about_tool = self.findChild(QtWidgets.QMenuBar, "AboutTool")

        self.encrButton = self.findChild(QtWidgets.QPushButton, "Encrypt")
        self.decrButton = self.findChild(QtWidgets.QPushButton, "Decrypt")
        self.saveButton = self.findChild(QtWidgets.QPushButton, "saveButton")

        # connecting to ui
        self.helpButton.clicked.connect(self.show_help_dialog)
        self.aboutButton.clicked.connect(self.about_dialog)

        

        self.CheckSamePath.stateChanged.connect(self.on_checkbox_toggle)

        self.buttonFileChoose.clicked.connect(self.choose_file)
        self.SavePathButton.clicked.connect(self.choose_path)
        self.donebutton.clicked.connect(QApplication.exit)

        # main encryption/decryption
        self.encrButton.clicked.connect(self.encryptFile)
        self.decrButton.clicked.connect(self.decryptFile)
        self.saveButton.clicked.connect(self.save_to_file)

        # Only allow non-whitespace characters
        regex = QtCore.QRegularExpression(r"\S+")  # \S means "any non-whitespace character"
        validator = QtGui.QRegularExpressionValidator(regex)

        self.aeskey.setValidator(validator)
        self.aesiv.setValidator(validator)
        

        


    def choose_file(self):
        self.file_path, _ = QFileDialog.getOpenFileName(self, "Choose File")
        if self.file_path:
            self.filePathlnEdit.setText(self.file_path)
            if self.CheckSamePath.isChecked():
                path = os.path.dirname(self.file_path)
                self.SavePathlnEdit.setText(path)

    def choose_path(self):
        
        if self.CheckSamePath.isChecked() and self.file_path:
            path=os.path.dirname(self.file_path)
            self.SavePathlnEdit.setText(path)
        else :
            self.dir_path = QFileDialog.getExistingDirectory(self, "Choose Path")
            if self.dir_path :
                self.SavePathlnEdit.setText(self.dir_path)

    def show_help_dialog(self):
        QMessageBox.information(
            self,
            "Help - AES File Tool",
            "This tool lets you:\n"
            "- Choose a file to encrypt or decrypt\n"
            "- Set the save directory\n"
            "- Use AES-256 encryption\n\n"
            "Tip: Check 'Save in same directory' to avoid browsing."
        )

    def about_dialog(self):
        QMessageBox.information(
            self,
            "About this tool\n",
            "This tools is used to Encrypt/Decrypt a file to .enc format\n"
            "The tools used to perform the operations are :\n\n"
            "1) Python - Crypto, PyQt6\n"
            "2) QT6\n\n"
        )

    def version_dialog(self):
        QMessageBox.information()

    def on_checkbox_toggle(self) :
        if self.CheckSamePath.isChecked() :
            self.SavePathlnEdit.setEnabled(False)
            self.SavePathButton.setEnabled(False)
            if self.file_path :
                path=os.path.dirname(self.file_path)
                self.SavePathlnEdit.setText(path)

        else :
            self.SavePathButton.setEnabled(True)
            self.SavePathlnEdit.setEnabled(True)
            self.SavePathlnEdit.clear()
         

    def encryptFile(self) :
        if self.file_path:
            self.callFileFunc = FileHandler(self.file_path,self.dir_path)
            dataToEncr = self.callFileFunc.readBinary()
            aes = AEShandler(dataToEncr)
            key = self.aeskey.text()
            value_key = key if key.strip() else None
            if value_key :
                iv = self.aesiv.text()
                value_iv = iv if iv.strip() else None
                if value_iv : 
                    hash_key = aes.generateKey(value_key)
                    hash_iv = aes.generateIV(value_iv)
                else : self.uierrorBox(3013)
            else : self.uierrorBox(3012)
            self.data = aes.encrypt()
            print(self.data.hex())
            return self.data
        else :
            self.uierrorBox(2103)

    def decryptFile(self) :
        if self.file_path :
            base, ext = os.path.splitext(self.file_path)
            if ext == ".enc" :
                self.callFileFunc = FileHandler(self.file_path)
                dataToDecr = self.callFileFunc.readBinary()
                aes = AEShandler(dataToDecr)
                key = self.aeskey.text()
                value_key = key if key.strip() else None
                if value_key :
                    iv = self.aesiv.text()
                    value_iv = iv if iv.strip() else None
                    if value_iv : 
                        hash_key = aes.generateKey(value_key)
                        hash_iv = aes.generateIV(value_iv)
                    else : self.uierrorBox(3013)
                else : self.uierrorBox(3012)
                data = aes.decrypt()
                print(data.hex())
                return data
            else :
                self.uierrorBox(1104)
        else : self.uierrorBox(2103)

    def save_to_file(self,saveData) :
        path = self.SavePathlnEdit.text()
        full_path = path if path.strip() else None
        if full_path :
            self.callFileFunc.write_binary(self.data)
            
        else: self.uierrorBox(2104)


    def uierrorBox(self,code):
        if code == 2103 :
            QMessageBox.information(
                self,
                "Error :- 2103 \n",
                "Enter The file to encrypt/decrypt"
            )
        elif code == 2104 :
            QMessageBox.information(
                self,
                "Error :- 2104 \n",
                "Enter the path to save the file to"
            )
        elif code == 3321 :
            QMessageBox.information(
                self,
                "Error :- 3321 \n",
                "Enter The path to save the file to\n"
                "You can click the checkbox to save the file to same directory as the file "
            )

        elif code == 1104 :
            QMessageBox.information(
                self,
                "Error :- 1104 \n",
                "The File is not decryptable\n"
                "Select the files with .enc extension"
            )

        elif code == 3012 :
            QMessageBox.information(
                self,
                "Error :- 3012 \n",
                "The key has not been provided\n"
                "To encrypt/decrypt the file please enter the key"
            )
        elif code == 3013 :
            QMessageBox.information(
                self,
                "Error :- 3013 \n",
                "The initialization vector has not been provided\n"
                "To remove any redundancy please enter iv"
            )

        else :
            QMessageBox.information(
                self,
                "Error :- 404 \n",
                "Error :- Something went wrong with the application"
                "Please restart the application and try again"
            )
            QApplication.exit()


class AEShandler :

    def __init__(self,message : bytes):
        self.key = None
        self.iv = None
        self.message = message

        
        self.cipherText = None
        self.plaintext = None

    def generateKey(self, secret : str) -> bytes:
        self.key = hashlib.sha256(secret.encode()).digest()
        return self.key


    def generateIV(self, initVector : str) :
        full_hash = hashlib.sha256(initVector.encode()).digest()
        self.iv = full_hash[:16]
        return self.iv

    def encrypt(self) :
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.cipherText = self.cipher.encrypt(pad(self.message, AES.block_size))
        return self.cipherText

    def decrypt(self) :
        self.decipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        self.plaintext = unpad(self.decipher.decrypt(self.cipherText), AES.block_size)
        return self.plaintext


class FileHandler :

    def __init__(self, read_path, save_path):
        self.path = read_path
        self.save_path = save_path
        self.data = None

    def readBinary(self) :
        with open(self.path, "rb") as f :
            self.data = f
            return f.read()


    def write_binary(self, data: bytes, metadata: dict = None, suffix: str = ".enc") -> str:
        
        
        original_path = pathlib.Path(self.path)
        output_dir = pathlib.Path(self.save_path)
        output_dir.mkdir(parents=True, exist_ok=True)  # ensure directory exists

        name, flag  = os.path.splitext(self.path)
        print("The extension is :- ",flag)

        # Construct output filename
        original_name = original_path.name  
        if flag == "encr":
            output_name = original_name + suffix
        else:  # decryption: remove suffix if present
            output_name = original_name
            if output_name.endswith(suffix):
                output_name = output_name[:-len(suffix)]  # e.g., "photo.jpg"

        output_path = output_dir / output_name

        # Write data (with optional metadata during encryption)
        with open(output_path, 'wb') as fb:
            if metadata and flag == "encr":
                meta_json = json.dumps(metadata).encode("utf-8")
                fb.write(struct.pack("I", len(meta_json)))  # 4-byte length prefix
                fb.write(meta_json)
                fb.write(data)
            else:
                fb.write(data)

        return str(output_path)

if __name__ == '__main__' :
    app=QtWidgets.QApplication(sys.argv)
    Window = UIHandler("UI/package.ui")
    Window.show()
    sys.exit(app.exec())


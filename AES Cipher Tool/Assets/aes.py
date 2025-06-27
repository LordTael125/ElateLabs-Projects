from Cryptodome.Cipher import AES
import hashlib
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from PyQt6.QtWidgets import QFileDialog, QApplication, QMessageBox
from PyQt6 import QtWidgets, uic ,QtCore, QtGui
import os, sys, json, struct, pathlib

def resource_path(relative_path):
    """Get absolute path to resource, compatible with PyInstaller."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.abspath(relative_path)

class UIHandler(QtWidgets.QMainWindow) :
    def __init__(self, path) :
        super(UIHandler, self).__init__()
        ui_path = resource_path(path)
        uic.loadUi(ui_path,self)

        self.uierrDict={2103:"fileMiss",2104:"SavePthMiss",1098:"nonENC",3012:"keyErr",3013:"ivErr"}
        self.status = {"encr","decr"}

        self.file_path = None
        self.dir_path = None
        self.data = None
        self.flag = None
        self.metadata = None

        


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
        options = QFileDialog.Option.DontUseNativeDialog
        self.file_path, _ = QFileDialog.getOpenFileName(self, "Choose File", "", "All Files (*)", options=options)

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
            self.dir_path = QFileDialog.getExistingDirectory(self, "Choose Path", options=QFileDialog.Option.DontUseNativeDialog)

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

    def complete_dialog(self,code):
        proc_box = {
            1001 : ("Encryption Complete","Encryption of the file has been completed\nPress Save to File to export encrypted File"),
            1002 : ("Decryption Complete","Decryption of the file has been completed\nPress Save to File to export decrypted File"),
            1003 : ("File Saved","The File has been saved to destination")
        }
        title,msg = proc_box.get(code,("Process Done","The process has been sucessfully been completed"))
        QMessageBox.information(self,title,msg)

    def on_checkbox_toggle(self) :
        if self.CheckSamePath.isChecked() :
            self.SavePathlnEdit.setEnabled(False)
            self.SavePathButton.setEnabled(False)
            if self.file_path :
                path=os.path.dirname(self.file_path)
                self.SavePathlnEdit.setText(path)
                self.dir_path=path

        else :
            self.SavePathButton.setEnabled(True)
            self.SavePathlnEdit.setEnabled(True)
            self.SavePathlnEdit.clear()
         
    def validate_and_set_keys(self, aes):
        key = self.aeskey.text().strip()
        iv = self.aesiv.text().strip()
        if not key:
            self.uierrorBox(3012)
            return False
        if not iv:
            self.uierrorBox(3013)
            return False
        aes.generateKey(key)
        aes.generateIV(iv)
        return True



    def encryptFile(self) :
        if self.file_path:
            self.callFileFunc = FileHandler(self.file_path,self.dir_path)
            dataToEncr = self.callFileFunc.readBinary()
            aes = AEShandler(plaintext=dataToEncr)
            if not self.validate_and_set_keys(aes) :
                return
            self.data = aes.encrypt()
            self.flag="encr"
            print(self.data.hex())
            self.complete_dialog(1001)
            return self.data
        else :
            self.uierrorBox(2103)

    def decryptFile(self) :
        if self.file_path :
            base, ext = os.path.splitext(self.file_path)
            if ext == ".enc" :
                self.callFileFunc = FileHandler(self.file_path,self.dir_path)
                dataToDecr, self.metadata = self.callFileFunc.read_binary_with_metadata()
                aes = AEShandler(cipherText=dataToDecr)
                if not self.validate_and_set_keys(aes) :
                    return
                self.data = aes.decrypt()
                self.flag="decr"
                print(self.data.hex())
                self.complete_dialog(1002)
                return self.data
            else :
                self.uierrorBox(1104)
        else : self.uierrorBox(2103)

    def save_to_file(self) :
        path = self.SavePathlnEdit.text()
        full_path = path if path.strip() else None
        self.dir_path=path
        if full_path :
            if self.flag == "encr" :
                self.metadata = {
                    "original_ext": os.path.splitext(self.file_path)[1]
                }
                self.callFileFunc.write_encrypted_binary(self.data,metadata=self.metadata)
            else:
                original_ext = self.metadata.get("original_ext") if self.metadata else None
                self.callFileFunc.write_decrypted_binary(self.data, original_ext=original_ext)
            self.complete_dialog(1003)
        else: self.uierrorBox(2104)


    def uierrorBox(self, code):
        error_map = {
            2103: ("Error :- 2103", "Enter the file to encrypt/decrypt"),
            2104: ("Error :- 2104", "Enter the path to save the file"),
            1104: ("Error :- 1104", "The File is not decryptable\nSelect the files with .enc extension"),
            3012: ("Error :- 3012", "The key has not been provided"),
            3013: ("Error :- 3013", "The IV has not been provided"),
            3321: ("Error :- 3321", "Enter path to save file or check the checkbox for same directory"),
        }
        title, msg = error_map.get(code, ("Error :- 404", "Unknown error. Restart the application."))
        QMessageBox.information(self, title, msg)
        if code not in error_map:
            QApplication.exit()


class AEShandler :

    def __init__(self, plaintext: bytes = None, cipherText: bytes = None):
        self.key = None
        self.iv = None
        self.message = plaintext
        self.cipherText = cipherText
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
        if self.cipherText is None:
            raise ValueError("cipherText is None — cannot decrypt!")
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
        
    def read_binary_with_metadata(self):
        with open(self.path, "rb") as f:
            length_data = f.read(4)
            if len(length_data) != 4:
                raise ValueError("Corrupted or missing metadata header")
            meta_len = struct.unpack("I", length_data)[0]
            metadata = json.loads(f.read(meta_len))
            data = f.read()
            return data, metadata



    def write_encrypted_binary(self, data: bytes, suffix:str=".enc", metadata: dict = None) -> str:
        original_path = pathlib.Path(self.path)
        output_dir = pathlib.Path(self.save_path)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_name = original_path.name + suffix
        output_path = output_dir / output_name

        with open(output_path, 'wb') as fb:
            if metadata:
                meta_json = json.dumps(metadata).encode("utf-8")
                fb.write(struct.pack("I", len(meta_json)))
                fb.write(meta_json)
            fb.write(data)

        return str(output_path)
    

    def write_decrypted_binary(self, data: bytes, original_ext=None) -> str:
        original_path = pathlib.Path(self.path)
        output_dir = pathlib.Path(self.save_path)
        output_dir.mkdir(parents=True, exist_ok=True)

        base_name = original_path.stem  # removes '.enc'

        if original_ext:
            output_name = base_name + original_ext
        else:
            output_name = base_name  # fallback

        output_path = output_dir / output_name

        with open(output_path, 'wb') as fb:
            fb.write(data)

        return str(output_path)

if __name__ == '__main__' :
    app=QtWidgets.QApplication(sys.argv)
    Window = UIHandler("UI/package.ui")
    Window.show()
    sys.exit(app.exec())


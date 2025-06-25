from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from PyQt6.QtWidgets import QFileDialog, QApplication, QMessageBox
from PyQt6 import QtWidgets, uic
import os, sys
# from qtpy.QtUiTools import QUiLoader

class UIHandler(QtWidgets.QMainWindow) :
    def __init__(self, path) :
        super(UIHandler, self).__init__()
        uic.loadUi(path,self)

        self.buttonFileChoose = self.findChild(QtWidgets.QToolButton , "FileChooseBut")
        self.SavePathButton = self.findChild( QtWidgets.QToolButton , "SaveToolButton")


        self.filePathlnEdit = self.findChild(QtWidgets.QLineEdit , "FilePathLine")
        self.SavePathlnEdit = self.findChild(QtWidgets.QLineEdit , "SavePathLnEdit")

        self.CheckSamePath = self.findChild(QtWidgets.QCheckBox, "SamePathCheck")

        self.helpButton = self.findChild(QtWidgets.QPushButton, "Help")
        self.encrButton = self.findChild(QtWidgets.QPushButton, "Encrypt")
        self.donebutton = self.findChild(QtWidgets.QPushButton, "Done")


        self.buttonFileChoose.clicked.connect(self.choose_file)
        self.SavePathButton.clicked.connect(self.choose_path)
        self.donebutton.clicked.connect(QApplication.exit)


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
            dir_path = QFileDialog.getExistingDirectory(self, "Choose Path")
            if dir_path :
                self.SavePathlnEdit.setText(dir_path)

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

class AEShandler :

    def __init__(self,key : bytes ,message : bytes):
        self.key = key
        self.message = message
        self.iv = get_random_bytes(32)
        
        self.cipherText = None
        self.plaintext = None

    def encrypt(self) :
        self.cipher = AES.new(self.key, AES.MODE_CBC)
        self.cipherText = self.cipher.encrypt(pad(self.message, AES.block_size))
        return self.cipherText

    def decrypt(self) :
        self.decipher = AES.new(key, AES.MODE_CBC, self.iv)
        self.plaintext = unpad(self.decipher.decrypt(self.cipherText), AES.block_size)
        return self.plaintext


class FileHandler :

    def __init__(self, path):
        self.path = path


    def readBinary(self) :
        with open(self.path, "rb") as f :
            return f.read()

    def writeBinary(self, data, suffix=".enc") :
        base, ext = os.path.splitext(self.path)
        newPath = base + suffix + ext
        with open(newPath, 'wb') as fb :
            fb.write(data)
        return newPath
    



key = get_random_bytes(32)
if __name__ == '__main__' :
    app=QtWidgets.QApplication(sys.argv)
    Window = UIHandler("UI/package.ui")
    Window.show()
    sys.exit(app.exec())
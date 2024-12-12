from PySide6.QtWidgets import ( 
    QWidget,
    QPushButton,
    QHBoxLayout,
    QVBoxLayout,
    QLabel,
    QLineEdit,
    QGroupBox,
    QFileDialog,
    QMessageBox,
    QComboBox,
)
from PySide6.QtGui import QPixmap # type: ignore

import os
import cv2 # type: ignore

from aes import encrypt_image, decrypt_image


class Widget(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("AES Image Encryption/Decryption")

        self.imageEncrypted = None
        self.decryptedImage = None
        self.imagefile = None

        ##* KEY
        key_label = QLabel("Key")
        self.key_line = QLineEdit()
        self.key_line.setPlaceholderText("Enter your key here")

        key_layout = QHBoxLayout()
        key_layout.addWidget(key_label)
        key_layout.addWidget(self.key_line)

        ## * Choose File
        self.file_dialog = QFileDialog(self)
        self.file_dialog.setFileMode(QFileDialog.AnyFile)

        upload_button = QPushButton("Choose Image")
        upload_button.clicked.connect(self.choose_image)
        self.image_label = QLabel()

        ## * Method
        mode = QGroupBox("Choose Method")

        encrypt = QPushButton("Encrypt")
        decrypt = QPushButton("Decrypt")

        encrypt.clicked.connect(self.enc_image)
        decrypt.clicked.connect(self.dec_image)

        self.mode_list = QComboBox()
        self.mode_list.addItems(["ECB", "CTR", "CFB", "CBC"])

        method_layout = QHBoxLayout()
        method_layout.addWidget(encrypt)
        method_layout.addWidget(decrypt)

        mode_layout = QVBoxLayout()
        mode_layout.addWidget(self.mode_list)
        mode_layout.addLayout(method_layout)
        mode.setLayout(mode_layout)

        clear = QPushButton("Clear")
        clear.clicked.connect(self.cls)

        layout = QVBoxLayout()
        layout.addLayout(key_layout)
        layout.addWidget(self.image_label)
        layout.addWidget(upload_button)
        layout.addWidget(mode)
        layout.addWidget(clear)
        self.setLayout(layout)

    def choose_image(self):
        self.image_label.clear()
        self.imagefile = self.file_dialog.getOpenFileName(
            parent=self,
            caption="select image",
            dir=os.getcwd(),
        )
        self.image_label.setPixmap(QPixmap(self.imagefile[0]))

    def enc_image(self):
        if not self.key_line.text():
            QMessageBox.critical(self, "No Key", "Please Enter a key", QMessageBox.Ok)
        else:
            if self.imagefile:
                image = cv2.imread(self.imagefile[0])
                try:
                    self.imageEncrypted = encrypt_image(
                        image, self.key_line.text(), self.mode_list.currentText()
                    )
                    self.image_label.setPixmap(QPixmap("ImageEncrypted.png"))
                    self.imagefile = None
                except:
                    QMessageBox.critical(
                        self,
                        "Invalid data",
                        "The key is wrong or the cipher mode is different",
                        QMessageBox.Ok,
                    )
            elif (not self.imagefile) and (self.decryptedImage is not None):
                try:
                    self.imageEncrypted = encrypt_image(
                        self.decryptedImage,
                        self.key_line.text(),
                        self.mode_list.currentText(),
                    )
                    self.image_label.setPixmap(QPixmap("ImageEncrypted.png"))
                except:
                    QMessageBox.critical(
                        self,
                        "Invalid data",
                        "The key is wrong or the cipher mode is different",
                        QMessageBox.Ok,
                    )
            else:
                QMessageBox.critical(
                    self, "No Image", "Please choose an image", QMessageBox.Ok
                )

    def dec_image(self):
        if not self.key_line.text():
            QMessageBox.critical(self, "No Key", "Please Enter a key", QMessageBox.Ok)
        else:
            if self.imagefile:
                self.imageEncrypted = cv2.imread(self.imagefile[0])
                try:
                    self.decryptedImage = decrypt_image(
                        self.imageEncrypted,
                        self.key_line.text(),
                        self.mode_list.currentText(),
                    )
                    self.image_label.setPixmap(QPixmap("decryptedImage.png"))
                    self.imagefile = None
                except:
                    QMessageBox.critical(
                        self,
                        "Invalid data",
                        "The key is wrong or the cipher mode is different",
                        QMessageBox.Ok,
                    )
            elif (not self.imagefile) and (self.imageEncrypted is not None):
                try:
                    self.decryptedImage = decrypt_image(
                        self.imageEncrypted,
                        self.key_line.text(),
                        self.mode_list.currentText(),
                    )
                    self.image_label.setPixmap(QPixmap("decryptedImage.png"))
                except:
                    QMessageBox.critical(
                        self,
                        "Invalid data",
                        "The key is wrong or the cipher mode is different",
                        QMessageBox.Ok,
                    )
            else:
                QMessageBox.critical(
                    self, "No Image", "Please choose an image", QMessageBox.Ok
                )

    def cls(self):
        self.image_label.clear()
        self.key_line.clear()
        self.imageEncrypted = None
        self.decryptedImage = None
        self.imagefile = None

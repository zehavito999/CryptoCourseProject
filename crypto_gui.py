import random
import registry
import serpent
from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_crypto_main_window(object):
    def setupUi(self, crypto_main_window):
        self.log_list=[]
        crypto_main_window.setObjectName("crypto_main_window")
        crypto_main_window.resize(900, 800)
        crypto_main_window.setWindowTitle("Encryption-Decryption mails")
        self.centralwidget = QtWidgets.QWidget(crypto_main_window)
        self.centralwidget.setObjectName("centralwidget")
        self.alice_text = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.alice_text.setGeometry(QtCore.QRect(50, 340, 300, 100))
        self.alice_text.setObjectName("alice_text")
        self.alice_private_key_line_edit = QtWidgets.QLineEdit(self.centralwidget)
        self.alice_private_key_line_edit.setGeometry(QtCore.QRect(210, 50, 480, 20))
        self.alice_private_key_line_edit.setText("")
        self.alice_private_key_line_edit.setObjectName("alice_private_key_line_edit")
        self.bob_private_key_line_edit = QtWidgets.QLineEdit(self.centralwidget)
        self.bob_private_key_line_edit.setGeometry(QtCore.QRect(210, 150, 480, 20))
        self.bob_private_key_line_edit.setObjectName("bob_private_key_line_edit")
        self.alice_p_key_label = QtWidgets.QLabel(self.centralwidget)
        self.alice_p_key_label.setGeometry(QtCore.QRect(50, 50, 141, 20))
        self.alice_p_key_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.alice_p_key_label.setObjectName("alice_p_key_label")
        self.alice_p_key_label.setText("Alice private key:")
        self.bob_p_key_label = QtWidgets.QLabel(self.centralwidget)
        self.bob_p_key_label.setGeometry(QtCore.QRect(50, 150, 131, 20))
        self.bob_p_key_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.bob_p_key_label.setObjectName("bob_p_key_label")
        self.bob_p_key_label.setText("Bob private key:")
        self.generate_shared_key_btn = QtWidgets.QPushButton(self.centralwidget)
        self.generate_shared_key_btn.setGeometry(QtCore.QRect(710, 253, 150, 28))
        self.generate_shared_key_btn.setObjectName("generate_shared_key_btn")
        self.generate_shared_key_btn.setText("Generate Shared Key")
        self.generate_shared_key_btn.clicked.connect(self.shared_key_func)
        self.shared_public_key_line_edit = QtWidgets.QLineEdit(self.centralwidget)
        self.shared_public_key_line_edit.setGeometry(QtCore.QRect(210, 260, 480, 20))
        self.shared_public_key_line_edit.setObjectName("shared_public_key_line_edit")
        self.shared_key_label = QtWidgets.QLabel(self.centralwidget)
        self.shared_key_label.setGeometry(QtCore.QRect(50, 260, 161, 20))
        self.shared_key_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.shared_key_label.setObjectName("shared_key_label")
        self.shared_key_label.setText("Shared private key:")
        self.bob_text = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.bob_text.setGeometry(QtCore.QRect(50, 580, 300, 100))
        self.bob_text.setObjectName("bob_text")
        self.alice_email_label = QtWidgets.QLabel(self.centralwidget)
        self.alice_email_label.setGeometry(QtCore.QRect(50, 310, 111, 16))
        self.alice_email_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.alice_email_label.setObjectName("alice_email_label")
        self.alice_email_label.setText("Alice email:")
        self.bob_email_label = QtWidgets.QLabel(self.centralwidget)
        self.bob_email_label.setGeometry(QtCore.QRect(50, 550, 111, 16))
        self.bob_email_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.bob_email_label.setObjectName("bob_email_label")
        self.bob_email_label.setText("Bob email:")
        self.encrypt_alice_btn = QtWidgets.QPushButton(self.centralwidget)
        self.encrypt_alice_btn.setGeometry(QtCore.QRect(50, 460, 150, 28))
        self.encrypt_alice_btn.setObjectName("encrypt_alice_btn")
        self.encrypt_alice_btn.setText("Send-Encrypt")
        self.encrypt_alice_btn.setEnabled(False)
        self.decrypt_alice_btn = QtWidgets.QPushButton(self.centralwidget)
        self.decrypt_alice_btn.setGeometry(QtCore.QRect(50, 500, 150, 28))
        self.decrypt_alice_btn.setObjectName("decrypt_alice_btn")
        self.decrypt_alice_btn.setText("Receive-Decrypt")
        self.decrypt_alice_btn.setEnabled(False)
        self.encrypt_bob_btn = QtWidgets.QPushButton(self.centralwidget)
        self.encrypt_bob_btn.setGeometry(QtCore.QRect(50, 700, 150, 28))
        self.encrypt_bob_btn.setObjectName("encrypt_bob_btn")
        self.encrypt_bob_btn.setText("Send-Encrypt")
        self.encrypt_bob_btn.setEnabled(False)
        self.decrypt_bob_btn = QtWidgets.QPushButton(self.centralwidget)
        self.decrypt_bob_btn.setGeometry(QtCore.QRect(50, 740, 150, 28))
        self.decrypt_bob_btn.setObjectName("decrypt_bob_btn")
        self.decrypt_bob_btn.setText("Receive-Decrypt")
        self.decrypt_bob_btn.setEnabled(False)
        self.alice_public_labl = QtWidgets.QLabel(self.centralwidget)
        self.alice_public_labl.setGeometry(QtCore.QRect(50, 90, 141, 20))
        self.alice_public_labl.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.alice_public_labl.setObjectName("alice_public_labl")
        self.alice_public_labl.setText("Alice public key:")
        self.bob_public_label = QtWidgets.QLabel(self.centralwidget)
        self.bob_public_label.setGeometry(QtCore.QRect(50, 190, 131, 20))
        self.bob_public_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.bob_public_label.setObjectName("bob_public_label")
        self.bob_public_label.setText("Bob public key:")
        self.alice_public_key_line_edit = QtWidgets.QLineEdit(self.centralwidget)
        self.alice_public_key_line_edit.setGeometry(QtCore.QRect(210, 90, 480, 20))
        self.alice_public_key_line_edit.setObjectName("alice_public_key_line_edit")
        self.bob_public_key_line_edit = QtWidgets.QLineEdit(self.centralwidget)
        self.bob_public_key_line_edit.setGeometry(QtCore.QRect(210, 190, 480, 20))
        self.bob_public_key_line_edit.setObjectName("bob_public_key_line_edit")
        self.generate_alice_btn = QtWidgets.QPushButton(self.centralwidget)
        self.generate_alice_btn.setGeometry(QtCore.QRect(710, 43, 150, 28))
        self.generate_alice_btn.setObjectName("generate_alice_btn")
        self.generate_alice_btn.setText("Generate Alice")
        self.generate_alice_btn.clicked.connect(self.alice_btn_func)
        self.generate_bob_btn = QtWidgets.QPushButton(self.centralwidget)
        self.generate_bob_btn.setGeometry(QtCore.QRect(710, 150, 150, 28))
        self.generate_bob_btn.setObjectName("generate_bob_btn")
        self.generate_bob_btn.setText("Generate Bob")
        self.generate_bob_btn.clicked.connect(self.bob_btn_func)
        self.log_text_edit = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.log_text_edit.setGeometry(QtCore.QRect(510, 340, 351, 341))
        self.log_text_edit.setObjectName("log_text_edit")
        self.logs_label = QtWidgets.QLabel(self.centralwidget)
        self.logs_label.setGeometry(QtCore.QRect(510, 310, 111, 20))
        self.logs_label.setStyleSheet("font: 10pt \"MS Shell Dlg 2\";")
        self.logs_label.setObjectName("logs_label")
        self.logs_label.setText("Logs:")
        crypto_main_window.setCentralWidget(self.centralwidget)
        QtCore.QMetaObject.connectSlotsByName(crypto_main_window)
        self.execute_curve()
        self.encrypt_alice_btn.clicked.connect(self.exchange_alice_email)
        self.decrypt_alice_btn.clicked.connect(self.decrypt_bob_email_to_alice)
        self.encrypt_bob_btn.clicked.connect(self.prep_to_rep_to_alice)
        self.decrypt_bob_btn.clicked.connect(self.exchange_bob_email)


    def alice_btn_func(self):
        """
        generate alice's keys
        """
        self.alice_private_key_line_edit.setText(hex(self.side_a_private_key))
        str_a_public=self.compress(self.side_a_public_key)
        self.alice_public_key_line_edit.setText(str_a_public)
        self.log_text_edit.appendPlainText("side a private key:\n{}\n". format(hex(self.side_a_private_key)))
        self.log_text_edit.appendPlainText("side a public key:\n{}\n". format(str_a_public))


    def bob_btn_func(self):
        self.bob_private_key_line_edit.setText(hex(self.side_b_priavte_key))
        str_b_public=self.compress(self.side_b_public_key)
        self.bob_public_key_line_edit.setText(str_b_public)
        self.log_text_edit.appendPlainText("side b private key:\n{}\n".format(hex(self.side_b_priavte_key)))
        self.log_text_edit.appendPlainText("side b public key:\n{}\n".format(str_b_public))

    def shared_key_func(self):
        self.shared_key_val=self.compress(self.side_a_shared_key)
        self.shared_public_key_line_edit.setText(self.shared_key_val)
        self.str_shared_key = self.shared_key_val[2:len(self.shared_key_val)]
        self.log_text_edit.appendPlainText("Equal shared keys:\n{}\n{}". format(self.side_a_shared_key == self.side_b_shared_key,self.side_a_shared_key))
        if self.shared_public_key_line_edit.text()!= "": #if there's an email
            self.encrypt_alice_btn.setEnabled(True)


    def exchange_alice_email(self): #encrypt alice button
        self.encrypt_alice_btn.setEnabled(True)
        self.decrypt_alice_btn.setEnabled(False)
        alice_email=self.alice_text.toPlainText()
        self.cipher_a_text=serpent.encrypt_text(alice_email,self.str_shared_key)
        # self.alice_text.appendPlainText("\nEncrypted email from Alice:\n{}\n".format(self.cipher_a_text))
        self.alice_text.clear()
        self.bob_text.appendPlainText("Encrypted email from Alice:\n{}\n".format(self.cipher_a_text))
        self.log_text_edit.appendPlainText("Alice's ciphered email:\n{}\n".format(self.cipher_a_text))
        self.decrypt_bob_btn.setEnabled(True)
        self.encrypt_alice_btn.setEnabled(False)


    def exchange_bob_email(self):
        self.decrypt_b_text=serpent.decrypt_text(self.cipher_a_text, self.str_shared_key)
        # self.bob_text.appendPlainText("Decrypted email from Alice:\n{}\n".format(self.decrypt_b_text))
        self.log_text_edit.appendPlainText("Decrypted email from Alice to Bob:\n{}\n".format(self.decrypt_b_text))
        self.encrypt_bob_btn.setEnabled(True)
        self.bob_text.clear()
        self.alice_text.clear()
        self.decrypt_bob_btn.setEnabled(False)
        self.encrypt_alice_btn.setEnabled(False)
        self.decrypt_alice_btn.setEnabled(False)

        # if self.decrypt_bob_btn.isEnabled():#means bob recieved an email from alice and now he need to reply
        #     self.encrypt_bob_btn.setEnabled(True)


    def prep_to_rep_to_alice(self):
        self.encrypt_bob_btn.setEnabled(False)
        bob_reply = self.bob_text.toPlainText()
        self.bob_reply_ciphered = serpent.encrypt_text(bob_reply, self.str_shared_key)
        self.bob_text.appendPlainText("Encrypted reply to Alice:\n{}\n".format(self.bob_reply_ciphered))
        self.log_text_edit.appendPlainText("Bob's ciphered email:\n{}\n".format(self.bob_reply_ciphered))
        self.bob_text.clear()

        self.decrypt_alice_btn.setEnabled(True)
        self.encrypt_alice_btn.setEnabled(False)
        self.decrypt_bob_btn.setEnabled(False)
        self.alice_text.appendPlainText("Encrypted email from Bob:\n{}\n".format(self.bob_reply_ciphered))
        self.decrypt_b_reply = serpent.decrypt_text(self.bob_reply_ciphered, self.str_shared_key)


    def decrypt_bob_email_to_alice(self):
        self.bob_text.clear()
        self.alice_text.clear()
        self.decrypt_alice_btn.setEnabled(False)
        # self.alice_text.appendPlainText("Decrypted email from Bob:\n{}\n".format(self.decrypt_b_reply))
        self.log_text_edit.appendPlainText("Decrypted email from Bob to Alice:\n{}\n".format(self.decrypt_b_reply))
        self.encrypt_alice_btn.setEnabled(True)
        self.encrypt_bob_btn.setEnabled(False)
        self.decrypt_bob_btn.setEnabled(False)



    def compress(self,pubKey):
        return hex(pubKey.x)

    def execute_curve(self):
        curve = registry.get_curve('secp256r1')
        if not curve.is_singular():
            self.log_text_edit.appendPlainText("The curve is not singular")
            self.log_text_edit.appendPlainText("\ny^2 = x^3 + %dx + %d (mod %d)\n" % (curve.a, curve.b, curve.field.p))
        self.side_a_private_key = random.randrange(1, (curve.field.p)-1) #alice's private key
        self.side_b_priavte_key = random.randrange(1, (curve.field.p)-1)#bob's private key
        self.side_a_public_key = self.side_a_private_key * curve.g #alice's public key
        self.side_b_public_key = self.side_b_priavte_key * curve.g #bob's public key
        self.side_a_shared_key = self.side_a_private_key * self.side_b_public_key
        self.side_b_shared_key = self.side_b_priavte_key * self.side_a_public_key

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    crypto_main_window = QtWidgets.QMainWindow()
    ui = Ui_crypto_main_window()
    ui.setupUi(crypto_main_window)
    crypto_main_window.show()
    sys.exit(app.exec_())

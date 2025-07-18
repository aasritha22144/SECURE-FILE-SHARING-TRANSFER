import os
import shutil
import hashlib
from twilio.rest import Client
from cryptography.fernet import Fernet
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QLabel, 
                            QFileDialog, QMessageBox, QLineEdit, QVBoxLayout, 
                            QWidget, QInputDialog)
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import json

UPLOADS_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
KEY_FILE = "key.key"
VERSIONS_FOLDER = "versions"
KEY_DISTRIBUTION_FILE = "key_distribution.json"

SENDER_EMAIL = "aasrithareddysg@gmail.com"
SENDER_PASSWORD = "zrfm fhnp xerg bjaq"

TWILIO_ACCOUNT_SID = "AC8d3ea9b5bfc25a6d98023ccc831a4528"
TWILIO_AUTH_TOKEN = "d96c9d7df5c7cf60bc6b121319c73956"
TWILIO_PHONE_NUMBER = "+916305356367"

try:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
except Exception as e:
    print("Error initializing Twilio client:", e)

class FileSharingServer:
    def __init__(self):
        if not os.path.exists(UPLOADS_FOLDER):
            os.makedirs(UPLOADS_FOLDER)
        if not os.path.exists(ENCRYPTED_FOLDER):
            os.makedirs(ENCRYPTED_FOLDER)
        if not os.path.exists(VERSIONS_FOLDER):
            os.makedirs(VERSIONS_FOLDER)
        if not os.path.exists(KEY_DISTRIBUTION_FILE):
            with open(KEY_DISTRIBUTION_FILE, 'w') as f:
                json.dump({}, f)
                
        if not os.path.exists(KEY_FILE):
            self.key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(self.key)
        else:
            with open(KEY_FILE, "rb") as key_file:
                self.key = key_file.read()
        self.cipher = Fernet(self.key)

    def encrypt_file(self, file_name, data):
        encrypted_data = self.cipher.encrypt(data)
        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, file_name)
        with open(encrypted_file_path, "wb") as file:
            file.write(encrypted_data)
        return encrypted_file_path

    def decrypt_file_with_key(self, encrypted_data, decryption_key):
        try:
            cipher = Fernet(decryption_key)
            return cipher.decrypt(encrypted_data)
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def store_key_for_receiver(self, file_name, receiver_email, key):
        try:
            with open(KEY_DISTRIBUTION_FILE, 'r') as f:
                key_distribution = json.load(f)
            
            if receiver_email not in key_distribution:
                key_distribution[receiver_email] = {}
                
            key_distribution[receiver_email][file_name] = key.decode()
            
            with open(KEY_DISTRIBUTION_FILE, 'w') as f:
                json.dump(key_distribution, f)
            return True
        except Exception as e:
            print(f"Error storing key: {e}")
            return False

    def get_key_for_receiver(self, file_name, receiver_email):
        try:
            with open(KEY_DISTRIBUTION_FILE, 'r') as f:
                key_distribution = json.load(f)
            return key_distribution.get(receiver_email, {}).get(file_name)
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None

    def hash_file(self, data):
        hash_object = hashlib.sha256()
        hash_object.update(data)
        return hash_object.hexdigest()

    def upload_file(self, file_name, data, receiver_email, show_encryption_process=False):
        file_path = os.path.join(UPLOADS_FOLDER, file_name)
        if os.path.exists(file_path):
            return None  # File already exists
            
        with open(file_path, "wb") as file:
            file.write(data)
            
        if show_encryption_process:
            print("Starting encryption process...")
            print("Step 1: Reading file content.")
            print("Step 2: Encrypting file content.")
            
        encrypted_file_path = self.encrypt_file(file_name, data)
        
        # Generate a unique key for this file and receiver
        file_key = Fernet.generate_key()
        self.store_key_for_receiver(file_name, receiver_email, file_key)
        
        return file_name, encrypted_file_path, file_key

    def download_file(self, file_name):
        file_path = os.path.join(UPLOADS_FOLDER, file_name)
        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                return file.read()
        else:
            return None

    def list_files(self):
        return os.listdir(UPLOADS_FOLDER)

    def create_version(self, file_name):
        file_path = os.path.join(UPLOADS_FOLDER, file_name)
        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                data = file.read()
            hash_value = self.hash_file(data)
            version_folder = os.path.join(VERSIONS_FOLDER, file_name)
            if not os.path.exists(version_folder):
                os.makedirs(version_folder)
            version_file_path = os.path.join(version_folder, hash_value)
            if not os.path.exists(version_file_path):
                shutil.copy(file_path, version_file_path)
                return True
        return False

class FileSharingClient:
    def __init__(self, server):
        self.server = server

    def send_email_notification(self, uploaded_file_name, encrypted_file_path, receiver_email, decryption_key):
        # Email content
        subject = f"File '{uploaded_file_name}' Upload Notification"
        body = f"""File '{uploaded_file_name}' has been uploaded and stored. 
Please find the encrypted file attached.

To decrypt the file, use the following key:
{decryption_key.decode()}

Keep this key secure and don't share it with anyone else."""

        # Create MIME object
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver_email
        msg['Subject'] = subject

        # Attach the body to the email
        msg.attach(MIMEText(body, 'plain'))

        # Attach the encrypted file to the email
        with open(encrypted_file_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename=encrypted_{uploaded_file_name}')
            msg.attach(part)

        # Start SMTP session and send email
        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            text = msg.as_string()
            server.sendmail(SENDER_EMAIL, receiver_email, text)
            server.quit()
            print("Email notification sent successfully.")
        except Exception as e:
            print("Error sending email notification:", e)

    def upload_file(self, file_path, receiver_email):
        show_encryption_process = QMessageBox.question(None, "Encryption Process", 
            "Do you want to see the encryption process?", QMessageBox.Yes | QMessageBox.No)
            
        if show_encryption_process == QMessageBox.Yes:
            show_encryption_process = True
        else:
            show_encryption_process = False

        if not os.path.exists(file_path):
            QMessageBox.critical(None, "File Not Found", f"File '{file_path}' not found.")
            return None
            
        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as file:
            data = file.read()
            
        result = self.server.upload_file(file_name, data, receiver_email, show_encryption_process=show_encryption_process)
        if result:
            uploaded_file_name, encrypted_file_path, decryption_key = result
            self.send_sms_notification(uploaded_file_name, encrypted_file_path, receiver_email)
            self.send_email_notification(uploaded_file_name, encrypted_file_path, receiver_email, decryption_key)
            return uploaded_file_name
        else:
            QMessageBox.critical(None, "File Upload Failed", "File already exists on the server.")
            return None

    def send_sms_notification(self, uploaded_file_name, encrypted_file_path, receiver_email):
        sms_message = f"""File '{uploaded_file_name}' has been uploaded and encrypted. 
Check your email for the decryption key and download instructions."""
        
        try:
            twilio_client.messages.create(
                to=receiver_email,
                from_=TWILIO_PHONE_NUMBER,
                body=sms_message
            )
            print("SMS notification sent successfully.")
        except Exception as e:
            print("Error sending SMS notification:", e)

    def download_and_decrypt_file(self, file_name, destination_folder, decryption_key):
        if not os.path.exists(destination_folder):
            QMessageBox.critical(None, "Folder Not Found", "Destination folder does not exist.")
            return None
            
        encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, file_name)
        if not os.path.exists(encrypted_file_path):
            QMessageBox.critical(None, "File Not Found", f"Encrypted file '{file_name}' not found.")
            return None
            
        with open(encrypted_file_path, "rb") as file:
            encrypted_data = file.read()
            
        decrypted_data = self.server.decrypt_file_with_key(encrypted_data, decryption_key)
        if not decrypted_data:
            QMessageBox.critical(None, "Decryption Failed", "Invalid decryption key or corrupted file.")
            return None
            
        file_path = os.path.join(destination_folder, file_name)
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
            
        return file_path

    def list_files(self):
        return self.server.list_files()

    def create_version(self, file_name):
        return self.server.create_version(file_name)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Document Sharing")
        self.setGeometry(200, 200, 800, 800)

        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Receiver Email
        self.receiver_email_label = QLabel("Receiver Email:")
        self.receiver_email_input = QLineEdit()
        layout.addWidget(self.receiver_email_label)
        layout.addWidget(self.receiver_email_input)

        # Operation Choice
        self.choice_button = QPushButton("Select Operation")
        self.choice_button.clicked.connect(self.handle_choice)
        layout.addWidget(self.choice_button)

        # Output Label
        self.output_label = QLabel("")
        self.output_label.setAlignment(QtCore.Qt.AlignCenter)
        self.output_label.setWordWrap(True)
        layout.addWidget(self.output_label)

        # Previous Executions
        self.previous_executions_label = QLabel("Previous Executions:")
        self.previous_executions_text = QLabel("")
        self.previous_executions_text.setWordWrap(True)
        layout.addWidget(self.previous_executions_label)
        layout.addWidget(self.previous_executions_text)

        self.previous_executions = []

    def handle_choice(self):
        operations = {
            'U': "Upload File",
            'D': "Download and Decrypt File",
            'L': "List Files",
            'V': "Create Version",
            'Q': "Quit"
        }
        
        operation, ok = QtWidgets.QInputDialog.getItem(
            self, 'Select Operation', 'Choose an operation:', 
            list(operations.values()), 0, False)
            
        if not ok:
            return
            
        operation_code = [k for k, v in operations.items() if v == operation][0]
        client = FileSharingClient(server)
        receiver_email = self.receiver_email_input.text()
        
        if operation_code == 'U':
            self.handle_upload(client, receiver_email)
        elif operation_code == 'D':
            self.handle_download_decrypt(client)
        elif operation_code == 'L':
            self.handle_list_files(client)
        elif operation_code == 'V':
            self.handle_create_version(client)
        elif operation_code == 'Q':
            self.close()
            
        self.update_previous_executions()

    def handle_upload(self, client, receiver_email):
        if not receiver_email:
            QMessageBox.warning(self, "Missing Information", "Please enter receiver's email address.")
            return
            
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Upload")
        if file_path:
            uploaded_file_name = client.upload_file(file_path, receiver_email)
            if uploaded_file_name:
                self.output_label.setText(f"File uploaded successfully: {uploaded_file_name}\nDecryption key sent to {receiver_email}")
                self.previous_executions.append(f"Uploaded file: {uploaded_file_name} to {receiver_email}")

    def handle_download_decrypt(self, client):
        files = client.list_files()
        if not files:
            QMessageBox.information(self, "No Files", "No files available for download.")
            return
            
        file_name, ok = QtWidgets.QInputDialog.getItem(
            self, "Select File", "Choose a file to download:", files, 0, False)
        if not ok or not file_name:
            return
            
        decryption_key, ok = QtWidgets.QInputDialog.getText(
            self, "Decryption Key", "Enter the decryption key for this file:")
        if not ok or not decryption_key:
            return
            
        destination_folder = QFileDialog.getExistingDirectory(self, "Select Destination Folder")
        if not destination_folder:
            return
            
        try:
            # Convert the key from string to bytes
            decryption_key = decryption_key.encode()
            
            file_path = client.download_and_decrypt_file(
                file_name, destination_folder, decryption_key)
                
            if file_path:
                self.output_label.setText(f"File decrypted and saved to:\n{file_path}")
                self.previous_executions.append(f"Downloaded and decrypted: {file_name}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to decrypt file: {str(e)}")

    def handle_list_files(self, client):
        files = client.list_files()
        if files:
            file_list = "\n".join(files)
            QMessageBox.information(self, "Available Files", f"Files on server:\n{file_list}")
            self.previous_executions.append("Listed available files")
        else:
            QMessageBox.information(self, "No Files", "No files available on server.")

    def handle_create_version(self, client):
        files = client.list_files()
        if not files:
            QMessageBox.information(self, "No Files", "No files available to create versions.")
            return
            
        file_name, ok = QtWidgets.QInputDialog.getItem(
            self, "Select File", "Choose a file to create version:", files, 0, False)
        if not ok or not file_name:
            return
            
        if client.create_version(file_name):
            self.output_label.setText(f"Version created for file: {file_name}")
            self.previous_executions.append(f"Created version for: {file_name}")
        else:
            QMessageBox.warning(self, "Error", "Failed to create version for the file.")

    def update_previous_executions(self):
        self.previous_executions_text.setText("\n".join(self.previous_executions[-5:]))  # Show last 5 executions

if __name__ == "__main__":
    app = QApplication([])
    server = FileSharingServer()
    window = MainWindow()
    window.show()
    app.exec_()
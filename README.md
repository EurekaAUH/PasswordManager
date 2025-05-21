# OKEYDOKEY PASSWORD MANAGER APPLICATION

To run the OkeyDokey Password Manager application, please follow the steps below:

===============================================================================================

✅ 1. Install Python

Make sure Python 3.9 or above is installed on your system.

You can download Python from the official website:
https://www.python.org/downloads/

Important: During installation, check the box that says “Add Python to PATH”.

===============================================================================================

📦 2. Install Required Python Libraries

Open a terminal or command prompt and run the following command to install all the required libraries:


    "pip install customtkinter cryptography pillow"

This will install:

customtkinter – for building the desktop GUI
cryptography – for password encryption using Fernet
pillow – for handling and displaying images in the app

===============================================================================================

📁 3. Download the Project Files

Download or clone the entire project folder.
Make sure the folder includes the following files (some files will be generated automatically after using the app):

PasswordManager/
├── Password Manager.py
├── Database/
├── Images Files/
└── README.md

Note: The savedcredentials, pin, and key files will be created after the user registers for the first time.

===============================================================================================

▶️ 4. Run the Application

Navigate to the project folder using your terminal or file explorer and run:

Password Manager.py

The GUI window should open, allowing you to register, log in, and start managing passwords securely.

===============================================================================================

❗ Troubleshooting

If you get a ModuleNotFoundError, make sure all required packages are installed correctly.

If the GUI doesn’t open, confirm that you’re using Python 3.9 or newer.

On macOS or Linux, you may need to use python3 instead of python.

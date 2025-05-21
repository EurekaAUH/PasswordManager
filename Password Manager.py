














# ----------------------------------- BEFORE STARTING THE APP, PLEASE READ THE README.md FILE FIRST!  ----------------------------------- #
















# IMPORTS
import customtkinter as ctk
import tkinter as tk
import os
import base64
import hashlib
from tkinter import messagebox, Listbox, Scrollbar
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw
import random
import string
import threading
import time
import shutil

eye_open_img = ctk.CTkImage(Image.open("Image Files\SeePassword-Icon.png"), size=(33, 33))
eye_closed_img = ctk.CTkImage(Image.open("Image Files\Hide-Icon.png"), size=(33, 33))

# KEY FILES 
KEY_FILE = "Database\key.key"
CREDENTIALS_FILE = "Database\savedcredentials.txt"

# USER-SPECIFIC FILES
CURRENT_USER = [None] 
credentials_lines = []

def get_user_files(username):
    base = "Database/"
    return {
        'CREDENTIALS_FILE': f"{base}{username}_credentials.txt",
        'PIN_FILE': f"{base}{username}_pin.hash",
        'KEY_FILE': f"{base}{username}_key.key"
    }

# --- PIN --- #
def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def is_pin_set():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    return os.path.exists(files['PIN_FILE']) and os.path.getsize(files['PIN_FILE']) > 0

def verify_pin(input_pin):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    if not is_pin_set():
        return False
    with open(files['PIN_FILE'], 'r') as f:
        stored_hash = f.read()
    return stored_hash == hash_pin(input_pin)

def set_pin(pin):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    with open(files['PIN_FILE'], 'w') as f:
        f.write(hash_pin(pin))

# --- PIN Prompt  --- #
def prompt_for_pin(callback):
    def submit():
        pin = pin_entry.get()
        if not pin.isdigit() or len(pin) != 4:
            pin_label.configure(text="PIN must be 4 digits.")
            return
        if verify_pin(pin):
            pin_window.destroy()
            callback(True)
        else:
            attempts[0] += 1
            if attempts[0] >= 5:
                pin_window.destroy()
                messagebox.showerror("Error", "Too many failed attempts.")
            else:
                pin_label.configure(text="Incorrect PIN. Try again.")

    attempts = [0]
    pin_window = ctk.CTkToplevel(app)
    pin_window.title("Enter PIN")
    pin_window.geometry("300x150")
    pin_label = ctk.CTkLabel(pin_window, text="Enter your PIN")
    pin_label.pack(pady=10)
    pin_entry = ctk.CTkEntry(pin_window, show="*")
    pin_entry.pack(pady=5)
    submit_btn = ctk.CTkButton(pin_window, text="Submit", command=submit)
    submit_btn.pack(pady=5)

def prompt_to_register_pin(callback):
    def register():
        pin = pin_entry.get()
        confirm = confirm_entry.get()
        if pin != confirm or not pin:
            pin_label.configure(text="PINs do not match or empty.")
        else:
            set_pin(pin)
            pin_window.destroy()
            callback(True)

    pin_window = ctk.CTkToplevel(app)
    pin_window.title("Set PIN")
    pin_window.geometry("300x200")
    pin_label = ctk.CTkLabel(pin_window, text="Set a new PIN")
    pin_label.pack(pady=10)
    pin_entry = ctk.CTkEntry(pin_window, placeholder_text="Enter PIN", show="*")
    pin_entry.pack(pady=5)
    confirm_entry = ctk.CTkEntry(pin_window, placeholder_text="Confirm PIN", show="*")
    confirm_entry.pack(pady=5)
    submit_btn = ctk.CTkButton(pin_window, text="Register", command=register)
    submit_btn.pack(pady=5)

# REGISTER PIN
def request_pin(callback):
    if is_pin_set():
        prompt_for_pin(callback)
    else:
        prompt_to_register_pin(callback)

# --- ENCRYPTION --- #
def generate_key(username):
    key = Fernet.generate_key()  # Generate a unique key
    files = get_user_files(username)
    with open(files['KEY_FILE'], "wb") as key_file:  # Save the key to a file
        key_file.write(key)
    return key

# Function to load an existing key from a file
def load_key(username):
    files = get_user_files(username)
    try:
        with open(files['KEY_FILE'], "rb") as key_file:
            key = key_file.read()  # Read the key from the file
        return key
    except FileNotFoundError:
        print(f"No key file found for user {username}.")
        return None

# Function to encrypt data using the user's key
def encrypt_data(data, username):
    key = load_key(username)
    if key is None:
        key = generate_key(username)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()  # Store as string

# Function to decrypt data using the user's key
def decrypt_data(encrypted_data, username):
    key = load_key(username)
    if key is None:
        print(f"No key file found for user {username}.")
        return None
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data.encode())  # Convert back to bytes
    return decrypted_data.decode()

# Configure CTk
ctk.set_appearance_mode("light")

# Files
CREDENTIALS_FILE = "savedcredentials.txt"
USER_CREDENTIALS_FILE = "Database/user_credentials.txt"
PIN_FILE = "pin.hash"
KEY_FILE = "key.key"

# App Window
app = ctk.CTk()
app.title("Password Manager")
app.geometry("600x750")

# --- Loading Dots Function ---
def show_loading_icon(parent):
    spinner = ctk.CTkProgressBar(parent, mode="indeterminate", width=150, height=15, corner_radius=5, fg_color="gray", progress_color="blue")
    spinner.place(relx=0.5, rely=0.7, anchor="center")  # Adjust relx/rely to fit
    spinner.start()
    
    return spinner  

# --- Button Command Function ---
def on_button_click():
    show_loading_icon(opening_frame)
    threading.Thread(target=lambda: (time.sleep(1), show_login()), daemon=True).start()

# ---------- PAGE FRAMES ---------- #
login_frame = ctk.CTkFrame(app)
register_frame = ctk.CTkFrame(app)
main_frame = ctk.CTkFrame(app)
add_frame = ctk.CTkFrame(app)
details_frame = ctk.CTkFrame(app)
view_frame = ctk.CTkFrame(app)
edit_frame = ctk.CTkFrame(app)  
opening_frame = ctk.CTkFrame(app)
mfa_frame = ctk.CTkFrame(app)

# Set all main frames' background color to white
login_frame.configure(fg_color="#FFFFFF")
register_frame.configure(fg_color="#FFFFFF")
main_frame.configure(fg_color="#FFFFFF")
add_frame.configure(fg_color="#FFFFFF")
details_frame.configure(fg_color="#FFFFFF")
view_frame.configure(fg_color="#FFFFFF")
edit_frame.configure(fg_color="#FFFFFF")
opening_frame.configure(fg_color="#FFFFFF")
mfa_frame.configure(fg_color="#FFFFFF")

# ---------- PAGE SWITCHING ---------- #
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    details_frame.pack_forget()
    main_frame.pack(fill="both", expand=True, padx=0, pady=0)
    refresh_main_credentials()

def show_add_password():
    # Reset save/back buttons to add mode
    add_save_btn.configure(text="Save", command=save_credentials)
    add_back_btn.configure(text="Back", command=show_main)
    main_frame.pack_forget()
    add_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_register():
    login_frame.pack_forget()
    register_frame.pack(fill="both", expand=True, padx=20, pady=20)

def back_to_login():
    register_frame.pack_forget()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

def logout():
    CURRENT_USER[0] = None

    for frame in (main_frame, add_frame, view_frame, edit_frame, mfa_frame, details_frame):
        frame.pack_forget()

    for widget in mfa_frame.winfo_children():
        widget.destroy()

    build_login_ui()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

# --- VALIDATION FUNCTIONS --- #
def validate_username(username):
    if not (6 <= len(username) <= 20):
        return False, "Username must be between 6 and 20 characters."
    return True, ""

def validate_password(password, username):
    if not (6 <= len(password) <= 20):
        return False, "Password must be between 6 and 20 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character."
    if username.lower() in password.lower():
        return False, "Password must not contain your username."
    return True, ""

def check_login():
    username = login_user_entry.get().strip()
    password = login_pass_entry.get().strip()

    if not (6 <= len(username) <= 20):
        login_error.configure(text="Username must be between 6 and 20 characters.")
        return

    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as f:
            for line in f:
                if not line.strip() or "," not in line:
                    continue 

                saved_user, saved_pass = line.strip().split(",")

                if saved_user == username and saved_pass == password:
                    files = get_user_files(username)
                    if not os.path.exists(files['CREDENTIALS_FILE']):
                        open(files['CREDENTIALS_FILE'], 'w').close()
                    if not os.path.exists(files['KEY_FILE']):
                        generate_key(username)

                    CURRENT_USER[0] = username
                    migrate_old_credentials_file(username)

                    login_count = increment_login_count(username)

                    def after_mfa():
                        show_main()

                    if login_count % 1 == 0:
                        show_mfa_verify_prompt_in_frame(username, login_frame, after_mfa)
                    else:
                        show_main()
                    return

    login_error.configure(text="Invalid credentials.")

def register_user():
    username = reg_user_entry.get().strip()
    password = reg_pass_entry.get().strip()
    confirm = reg_confirm_entry.get().strip()

    username_valid, username_error = validate_username(username)
    if not username_valid:
        reg_error.configure(text=username_error)
        return

    password_valid, password_error = validate_password(password, username)
    if not password_valid:
        reg_error.configure(text=password_error)
        return

    if not username or not password:
        reg_error.configure(text="All fields are required.")
    elif password != confirm:
        reg_error.configure(text="Passwords do not match.")
    else:
        if os.path.exists(USER_CREDENTIALS_FILE):
            with open(USER_CREDENTIALS_FILE, "r") as f:
                for line in f:
                    if username == line.strip().split(",")[0]:
                        reg_error.configure(text="Username already exists.")
                        return
        
        files = get_user_files(username)
        open(files['CREDENTIALS_FILE'], 'w').close()
        generate_key(username)
        
        with open(USER_CREDENTIALS_FILE, "a") as f:
            f.write(f"{username},{password}\n")
        
        CURRENT_USER[0] = username
        show_mfa_prompt_in_frame(username, register_frame, back_to_login)

def show_mfa_prompt_in_frame(username, mfa_frame, on_success):
    for widget in mfa_frame.winfo_children():
        widget.forget()
    mfa_frame.configure(fg_color="white")
    
    mfa_bg = ctk.CTkImage(
        light_image=Image.open("Image Files\MFA.png"),
        size=(600, 750)
    )
    mfa_bg_label = ctk.CTkLabel(mfa_frame, image=mfa_bg, text="")
    mfa_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

    predefined_questions = [
        "What is your childhood nickname?",
        "What was the first dish you \n learned how to cook?",
        "Who was your first crush?",
        "What is the first name of your \n oldest cousin?",
        "When is the birthday of your best friend?",
    ]

    border_frame = ctk.CTkFrame(mfa_frame, fg_color="black")
    border_frame.place(relx=0.5, rely=0.55, anchor="center")

    question_dropdown = ctk.CTkOptionMenu(border_frame, values=predefined_questions,
                                      fg_color="white", button_color="white", button_hover_color="#FEF5F5",
                                      text_color="black", dropdown_fg_color="white", dropdown_text_color="black",
                                      width=275, height=55, corner_radius=70, 
                                      font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18, weight="bold"))
    question_dropdown.set("Select a question")
    question_dropdown.pack(padx=4, pady=4)

    answer_entry = ctk.CTkEntry(mfa_frame, placeholder_text="Enter Answer",
                            placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9",
                            width=300, height=50,
                            font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20))
    answer_entry.place(relx=0.5, rely=0.67, anchor="center")

    mfa_error = ctk.CTkLabel(mfa_frame, text="", text_color="red")
    mfa_error.place(relx=0.5, rely=0.75, anchor="center", y=-10)

    def save_mfa():
        question = question_dropdown.get().strip()
        answer = answer_entry.get().strip()
        if question == "Select a question" or not answer:
            mfa_error.configure(text="Please select a question and enter an answer.", text_color="red")
            return
        files = get_user_files(username)
        mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
        with open(mfa_file, 'w') as f:
            f.write(question + '\n')
            f.write(answer + '\n')
        mfa_error.configure(text="MFA question set!", text_color="green")
        mfa_frame.after(1000, on_success)

    mfa_save_btn = ctk.CTkButton(mfa_frame, text="SAVE", width=275, height=55,
                         font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                         command=save_mfa, text_color="black", fg_color="transparent",
                         border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    mfa_save_btn.place(relx=0.5, rely=0.8, anchor="center")

def show_mfa_verify_prompt_in_frame(username, parent_frame, on_success):
    for widget in parent_frame.winfo_children():
        widget.destroy()
    parent_frame.configure(fg_color="white")

    files = get_user_files(username)
    mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
    if not os.path.exists(mfa_file):
        on_success()
        return
    with open(mfa_file, 'r') as f:
        question = f.readline().strip()
        correct_answer = f.readline().strip()

    mfa_bg = ctk.CTkImage(
        light_image=Image.open("Image Files\MFA.png"),
        size=(600, 750)
    )
    mfa_bg_label = ctk.CTkLabel(parent_frame, image=mfa_bg, text="")
    mfa_bg_label.place(relx=0.5, rely=0.5, anchor="center")

    mfa_question = ctk.CTkLabel(parent_frame, text=question,
                                font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=22, weight="bold"),
                                text_color="black")
    mfa_question.place(relx=0.5, rely=0.51, anchor="center")

    answer_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Answer",
                                placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9",
                                width=300, height=50,
                                font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20))
    answer_entry.place(relx=0.5, rely=0.58, anchor="center")

    mfa_error = ctk.CTkLabel(parent_frame, text="", text_color="red")
    mfa_error.place(relx=0.5, rely=0.64, anchor="center")

    def check_answer():
        answer = answer_entry.get().strip()
        if answer.lower() == correct_answer.lower():
            mfa_error.configure(text="Correct!", text_color="green")
            parent_frame.after(500, on_success)
        else:
            mfa_error.configure(text="Incorrect answer. Try again.", text_color="red")

    def go_back():
        back_to_login()

    login_btn = ctk.CTkButton(parent_frame, text="LOGIN", width=275, height=55,
                              font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                              command=check_answer, text_color="black", fg_color="transparent",
                              border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    login_btn.place(relx=0.5, rely=0.7, anchor="center")

    mfa_back_btn = ctk.CTkButton(parent_frame, text="GO BACK", width=275, height=55,
                             font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                             command=go_back, text_color="black", fg_color="transparent",
                             border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    mfa_back_btn.place(relx=0.5, rely=0.8, anchor="center")

# ---------- SAVE & CLEAR ---------- #
def save_credentials():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    category = category_entry.get().strip()
    
    if category == "Login":
        entry_type = type_entry.get().strip()
        entry_email = email_entry.get().strip()
        entry_password = password_entry.get().strip()
        
        if not all([entry_type, entry_email, entry_password]):
            messagebox.showwarning("Missing Fields", "Please fill in all fields.")
            return
            
        encrypted_password = encrypt_data(entry_password, username)
        with open(files['CREDENTIALS_FILE'], "a") as f:
            f.write(f"Login|{entry_type}|{entry_email}|{encrypted_password}\n")
            
    elif category == "Credit Card":
        card_name = card_name_entry.get().strip()
        card_number = card_number_entry.get().strip()
        card_expiry = card_expiry_entry.get().strip()
        card_cvv = card_cvv_entry.get().strip()
        
        if not all([card_name, card_number, card_expiry, card_cvv]):
            messagebox.showwarning("Missing Fields", "Please fill in all card fields.")
            return
            
        encrypted_cvv = encrypt_data(card_cvv, username)
        with open(files['CREDENTIALS_FILE'], "a") as f:
            f.write(f"Credit Card|{card_name}|{card_number}|{card_expiry}|{encrypted_cvv}\n")
            
    elif category == "Notes":
        title = notes_title_entry.get().strip()
        content = notes_content.get("1.0", ctk.END).strip()
        
        if not all([title, content]):
            messagebox.showwarning("Missing Fields", "Please fill in title and content.")
            return
            
        encrypted_content = encrypt_data(content, username)
        with open(files['CREDENTIALS_FILE'], "a") as f:
            f.write(f"Notes|{title}|{encrypted_content}\n")
    
    clear_inputs()
    messagebox.showinfo("Success", "Credentials saved securely.")

def clear_inputs():
    type_entry.delete(0, ctk.END)
    email_entry.delete(0, ctk.END)
    password_entry.delete(0, ctk.END)
    card_name_entry.delete(0, ctk.END)
    card_number_entry.delete(0, ctk.END)
    card_expiry_entry.delete(0, ctk.END)
    card_cvv_entry.delete(0, ctk.END)
    notes_title_entry.delete(0, ctk.END)
    notes_content.delete("1.0", ctk.END)

# ---------- LOAD & DISPLAY CREDENTIALS ---------- #
def parse_user_credentials(username):
    files = get_user_files(username)
    if not os.path.exists(files['CREDENTIALS_FILE']):
        return {}
    
    with open(files['CREDENTIALS_FILE'], "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    
    credentials_by_category = {}
    for line in lines:
        parts = line.split("|")
        if len(parts) >= 2:
            category = parts[0]
            if category not in credentials_by_category:
                credentials_by_category[category] = []
            credentials_by_category[category].append(parts[1:])
    return credentials_by_category

# ---------- EDIT PASSWORDS FUNCTIONALITY ---------- #
show_passwords = False

def toggle_password_visibility():
    global show_passwords, visibility_switch

    def on_pin_verified(success):
        global show_passwords
        if success:
            show_passwords = not show_passwords
            if show_passwords:
                visibility_switch.select()
            else:
                visibility_switch.deselect()
            load_credentials()
        else:
            show_passwords = False
            visibility_switch.deselect()
            load_credentials()
    request_pin(on_pin_verified)

visibility_switch = ctk.CTkSwitch(
    master=view_frame,
    text="Show Passwords",
    command=toggle_password_visibility
)
visibility_switch.pack(pady=5)

def load_credentials():
    global credentials_lines
    username = CURRENT_USER[0]
    files = get_user_files(username)
    credentials_lines = []

    for widget in view_frame.winfo_children():
        widget.forget()

    if not os.path.exists(files['CREDENTIALS_FILE']):
        return

    with open(files['CREDENTIALS_FILE'], 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    credentials_lines = lines

    for idx, line in enumerate(lines):
        parts = line.split("|")
        category = parts[0]

        if category == "Login" and len(parts) >= 4:
            entry_type, email = parts[1:3]
            label_text = f"Type: {entry_type} | Email: {email} | Password: *****"
        elif category == "Credit Card" and len(parts) >= 5:
            name, number, expiry = parts[1:4]
            label_text = f"Name: {name} | Number: {number} | Expiry: {expiry} | CVV: *****"
        elif category == "Notes" and len(parts) >= 3:
            title = parts[1]
            label_text = f"Title: {title} | Content: *****"
        else:
            continue

        entry_button = ctk.CTkButton(view_frame, text=label_text, anchor="w", width=600,
                                     command=lambda i=idx, p=parts, c=category: show_credential_details(i, p, c, credentials_lines))
        entry_button.pack(fill="x", padx=10, pady=5)

def edit_credential_in_page(parts, original_line):
    global credentials_lines
    username = CURRENT_USER[0]
    files = get_user_files(username)

    if os.path.exists(files['CREDENTIALS_FILE']):
        with open(files['CREDENTIALS_FILE'], 'r') as f:
            credentials_lines = [line.strip() for line in f if line.strip()]

    def on_pin_verified(success):
        if not success:
            messagebox.showerror("Error", "PIN verification failed. Cannot edit credential.")
            return
        build_edit_page(edit_frame, original_line, on_save, on_back)
        main_frame.pack_forget()
        edit_frame.pack(fill="both", expand=True)

    def on_save(old_line, new_line):
        try:
            idx = credentials_lines.index(old_line)
            credentials_lines[idx] = new_line
        except ValueError:
            credentials_lines.append(new_line)
        update_credentials_file()
        messagebox.showinfo("Success", "Credential updated.")
        show_main()
        load_credentials()

    def on_back():
        show_main()

    request_pin(on_pin_verified)

def write_credentials_file():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    with open(files['CREDENTIALS_FILE'], "w") as f:
        for line in credentials_lines:
            f.write(f"{line}\n")

def update_credentials_file():
    global credentials_lines
    username = CURRENT_USER[0]
    files = get_user_files(username)
    with open(files['CREDENTIALS_FILE'], "w") as f:
        for line in credentials_lines:
            f.write(line + "\n")

def get_login_count(username):
    files = get_user_files(username)
    count_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_login_count.txt')
    if not os.path.exists(count_file):
        return 0
    with open(count_file, 'r') as f:
        try:
            return int(f.read().strip())
        except:
            return 0

def increment_login_count(username):
    files = get_user_files(username)
    count_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_login_count.txt')
    count = get_login_count(username) + 1
    with open(count_file, 'w') as f:
        f.write(str(count))
    return count

# ---------- START THE APP ---------- #
def show_login():
    opening_frame.pack_forget()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

opening_bg = ctk.CTkImage(
    light_image=Image.open("Image Files\Welcome-Page.png"),
    size=(600, 750)
)

opening_bg_label = ctk.CTkLabel(opening_frame, image=opening_bg, text="")
opening_bg_label.place(relx=0.5, rely=0.5, anchor="center")

get_started_btn = ctk.CTkButton(opening_frame, text="Get Started!", width=300, height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"),
    command=lambda: on_button_click(), text_color="black", fg_color="white",
    border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
get_started_btn.place(relx=0.5, rely=0.8, anchor="center")

opening_frame.pack(fill="both", expand=True, padx=20, pady=20)

# ---------- LOGIN PAGE ---------- #
for widget in login_frame.winfo_children():
    widget.destroy()

login_bg = ctk.CTkImage(
    light_image=Image.open("Image Files\LogIn-Page.png"),
    size=(600, 750)
)

login_bg_label = ctk.CTkLabel(login_frame, image=login_bg, text="")
login_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

login_user_entry = ctk.CTkEntry(login_frame, placeholder_text="Username", placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9", width=300, height=50, font=ctk.CTkFont(size=20))
login_user_entry.place(relx=0.5, rely=0.43, anchor="center")
login_frame.configure(fg_color="#FEFEFE")

login_pass_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
login_pass_frame.place(relx=0.52, rely=0.55, anchor="center")
login_pass_entry = ctk.CTkEntry(login_pass_frame, placeholder_text="Password", show="*", placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9", width=255, height=40, font=ctk.CTkFont(size=20))
login_pass_entry.pack(side="left", ipadx=4, ipady=4)

login_pw_visible = [False]

def toggle_login_pw():
    if login_pw_visible[0]:
        login_pass_entry.configure(show="*")
        login_eye_btn.configure(image=eye_open_img)
    else:
        login_pass_entry.configure(show="")
        login_eye_btn.configure(image=eye_closed_img)
    login_pw_visible[0] = not login_pw_visible[0]

login_eye_btn = ctk.CTkButton(
    login_pass_frame,
    image=eye_open_img,
    text="",
    width=32,
    height=32,
    fg_color="#FEFEFE",
    hover_color="#FEFEFE",
    command=toggle_login_pw
)

login_eye_btn.pack(side="left", padx=0)
login_eye_btn.bind("<Enter>", lambda e: login_eye_btn.configure(text_color="#5F5F5F") if not login_pw_visible[0] else None)
login_eye_btn.bind("<Leave>", lambda e: login_eye_btn.configure(text_color="#D9D9D9") if not login_pw_visible[0] else None)

login_eye_btn.pack(side="left", padx=0)
login_eye_btn.pack(side="left", padx=0)

login_error = ctk.CTkLabel(login_frame, text="", text_color="red")
login_error.place(relx=0.48, rely=0.65, anchor="center")


login_button = ctk.CTkButton(login_frame, text="LOG IN", width=300, height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
    command=check_login, text_color="black", fg_color="transparent",
    border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
login_button.place(relx=0.5, rely=0.73, anchor="center")

register_link = ctk.CTkButton(login_frame, text="DON'T HAVE ACCOUNT?", width=300, height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
    command=show_register, text_color="black", fg_color="transparent",
    border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
register_link.place(relx=0.5, rely=0.84, anchor="center")

def build_login_ui():
    global login_user_entry, login_pass_entry, login_error, login_eye_btn, login_pw_visible

    for widget in login_frame.winfo_children():
        widget.destroy()

    login_bg = ctk.CTkImage(
        light_image=Image.open("Image Files\LogIn-Page.png"),
        size=(600, 750)
    )
    login_bg_label = ctk.CTkLabel(login_frame, image=login_bg, text="")
    login_bg_label.image = login_bg 
    login_bg_label.place(relx=0.5, rely=0.5, anchor="center")

    login_frame.configure(fg_color="#FEFEFE")

    login_user_entry = ctk.CTkEntry(
        login_frame, placeholder_text="Username", placeholder_text_color="#D9D9D9",
        fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9",
        width=300, height=50, font=ctk.CTkFont(size=20)
    )
    login_user_entry.place(relx=0.5, rely=0.43, anchor="center")

    login_pass_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
    login_pass_frame.place(relx=0.52, rely=0.55, anchor="center")

    login_pass_entry = ctk.CTkEntry(
        login_pass_frame, placeholder_text="Password", show="*",
        placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black",
        border_color="#D9D9D9", width=255, height=40, font=ctk.CTkFont(size=20)
    )
    login_pass_entry.pack(side="left", ipadx=4, ipady=4)

    login_pw_visible = [False]

    def toggle_login_pw():
        if login_pw_visible[0]:
            login_pass_entry.configure(show="*")
            login_eye_btn.configure(image=eye_open_img)
        else:
            login_pass_entry.configure(show="")
            login_eye_btn.configure(image=eye_closed_img)
        login_pw_visible[0] = not login_pw_visible[0]

    login_eye_btn = ctk.CTkButton(
        login_pass_frame,
        image=eye_open_img,
        text="",
        width=32,
        height=32,
        fg_color="#FEFEFE",
        hover_color="#FEFEFE",
        command=toggle_login_pw
    )
    
    login_eye_btn.bind("<Enter>", lambda e: login_eye_btn.configure(text_color="#5F5F5F") if not login_pw_visible[0] else None)
    login_eye_btn.bind("<Leave>", lambda e: login_eye_btn.configure(text_color="#D9D9D9") if not login_pw_visible[0] else None)
    login_eye_btn.pack(side="left", padx=0)

    login_error = ctk.CTkLabel(login_frame, text="", text_color="red")
    login_error.place(relx=0.48, rely=0.65, anchor="center")

    login_button = ctk.CTkButton(
        login_frame, text="LOG IN", width=300, height=60,
        font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
        command=check_login, text_color="black", fg_color="transparent",
        border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50
    )
    login_button.place(relx=0.5, rely=0.73, anchor="center")

    register_link = ctk.CTkButton(
        login_frame, text="DON'T HAVE ACCOUNT?", width=300, height=60,
        font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
        command=show_register, text_color="black", fg_color="transparent",
        border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50
    )
    register_link.place(relx=0.5, rely=0.84, anchor="center")

    forgot_password_btn = ctk.CTkButton(
        login_frame,
        text="Forgot Password?",
        fg_color="transparent",
        text_color="blue",
        hover_color="#e6e6ff",
        font=ctk.CTkFont(size=14, underline=True),
        corner_radius=0,
        command=lambda: start_forgot_password_flow(login_user_entry.get().strip())
    )
    forgot_password_btn.place(relx=0.5, rely=0.62, anchor="center")

def show_new_password_window(username, on_password_confirmed):
    window = ctk.CTkToplevel()
    window.title("Set New Password")
    window.geometry("600x500")
    window.resizable(False, False)
    window.configure(fg_color="white")

    okdkey_img = ctk.CTkImage(light_image=Image.open("Image Files\Logo.png"), size=(150, 150))
    okdkey_logo_label = ctk.CTkLabel(window, image=okdkey_img, text="")
    okdkey_logo_label.place(relx=0.5, rely=0.1, anchor="center")

    pw_visible = [False]

    req_frame = ctk.CTkFrame(window, fg_color="white")
    req_frame.place(relx=0.5, rely=0.62, anchor="center")
    req_font = ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12)
    length_req = ctk.CTkLabel(req_frame, text="• 6-20 characters", text_color="gray", font=req_font)
    upper_req = ctk.CTkLabel(req_frame, text="• One uppercase letter", text_color="gray", font=req_font)
    number_req = ctk.CTkLabel(req_frame, text="• One number", text_color="gray", font=req_font)
    special_req = ctk.CTkLabel(req_frame, text="• One special character", text_color="gray", font=req_font)
    for label in [length_req, upper_req, number_req, special_req]:
        label.pack(anchor="w", pady=1)

    new_pw_frame = ctk.CTkFrame(window, fg_color="white", width=300, height=50)
    new_pw_frame.place(relx=0.5, rely=0.32, anchor="center")
    new_pw_entry = ctk.CTkEntry(
        new_pw_frame,
        placeholder_text="New Password",
        placeholder_text_color="#D9D9D9",
        show="*",
        fg_color="#FEFEFE",
        border_color="#D9D9D9",
        border_width=1,
        corner_radius=6,
        width=250,
        height=40,
        font=ctk.CTkFont(size=20),
        text_color="black"
    )
    new_pw_entry.pack(side="left")

    confirm_pw_frame = ctk.CTkFrame(window, fg_color="white", width=300, height=50)
    confirm_pw_frame.place(relx=0.5, rely=0.42, anchor="center")
    confirm_pw_entry = ctk.CTkEntry(
        confirm_pw_frame,
        placeholder_text="Confirm Password",
        placeholder_text_color="#D9D9D9",
        show="*",
        fg_color="#FEFEFE",
        border_color="#D9D9D9",
        border_width=1,
        corner_radius=6,
        width=250,
        height=40,
        font=ctk.CTkFont(size=20),
        text_color="black"
    )
    confirm_pw_entry.pack(side="left")

    def toggle_pw_visibility():
        if pw_visible[0]:
            new_pw_entry.configure(show="*")
            confirm_pw_entry.configure(show="*")
            new_eye_btn.configure(image=eye_open_img)
            confirm_eye_btn.configure(image=eye_open_img)
        else:
            new_pw_entry.configure(show="")
            confirm_pw_entry.configure(show="")
            new_eye_btn.configure(image=eye_closed_img)
            confirm_eye_btn.configure(image=eye_closed_img)
        pw_visible[0] = not pw_visible[0]

    new_eye_btn = ctk.CTkButton(
        new_pw_frame, image=eye_open_img, text="", width=32, height=32,
        fg_color="#FEFEFE", hover_color="#FEFEFE",
        command=toggle_pw_visibility
    )
    new_eye_btn.pack(side="left", padx=0)

    confirm_eye_btn = ctk.CTkButton(
        confirm_pw_frame, image=eye_open_img, text="", width=32, height=32,
        fg_color="#FEFEFE", hover_color="#FEFEFE",
        command=toggle_pw_visibility
    )
    confirm_eye_btn.pack(side="left", padx=0)

    def update_password_requirements(event=None):
        password = new_pw_entry.get()
        unmet = 0
        if 6 <= len(password) <= 20:
            length_req.pack_forget()
        else:
            length_req.pack(anchor="w", pady=1)
            unmet += 1
        if any(c.isupper() for c in password):
            upper_req.pack_forget()
        else:
            upper_req.pack(anchor="w", pady=1)
            unmet += 1
        if any(c.isdigit() for c in password):
            number_req.pack_forget()
        else:
            number_req.pack(anchor="w", pady=1)
            unmet += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            special_req.pack_forget()
        else:
            special_req.pack(anchor="w", pady=1)
            unmet += 1
        if unmet == 0:
            req_frame.place_forget()
        else:
            if not req_frame.winfo_ismapped():
                req_frame.place(relx=0.5, rely=0.60, anchor="center")

    new_pw_entry.bind("<KeyRelease>", update_password_requirements)

    msg_label = ctk.CTkLabel(window, text="", text_color="red")
    msg_label.place(relx=0.5, rely=0.7, anchor="center")

    def reset_password():
        new_pw = new_pw_entry.get().strip()
        confirm_pw = confirm_pw_entry.get().strip()
        update_password_requirements()
        if not new_pw or not confirm_pw:
            msg_label.configure(text="Please fill all password fields.")
            return
        if new_pw != confirm_pw:
            msg_label.configure(text="Passwords do not match.")
            return
        if req_frame.winfo_ismapped():
            msg_label.configure(text="Password does not meet all requirements.")
            return
        window.destroy()
        on_password_confirmed(new_pw)

    submit_btn = ctk.CTkButton(
        window,
        text="NEXT",
        width=200,
        height=50,
        font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
        command=reset_password,
        text_color="black",
        fg_color="transparent",
        border_color="black",
        border_width=2,
        hover_color="#FEF5F5",
        corner_radius=50
    )
    submit_btn.place(relx=0.5, rely=0.85, anchor="center")

def show_message_window(msg):
    popup = ctk.CTkToplevel()
    popup.title("Error")
    popup.geometry("300x100")
    popup.resizable(False, False)
    label = ctk.CTkLabel(popup, text=msg, text_color="blue")
    label.pack(expand=True, pady=20)
    ok_btn = ctk.CTkButton(popup, text="OK", command=popup.destroy)
    ok_btn.pack(pady=5)

def show_error_and_return_to_login(msg):
    popup = ctk.CTkToplevel()
    popup.title("Error")
    popup.geometry("300x120")
    popup.resizable(False, False)
    label = ctk.CTkLabel(popup, text=msg, text_color="blue")
    label.pack(expand=True, pady=20)

    def close_popup_and_return():
        popup.destroy()
        build_login_ui() 

    popup.after(1500, close_popup_and_return)

def start_forgot_password_flow(username):
    if not username:
        show_message_window("Enter username!")
        return

    def on_new_password_confirmed(new_password):
        def after_mfa():
            def after_pin(success_pin):
                if success_pin:
                    update_password_file(username, new_password)
                    show_message_window("Password reset successful!")
                    build_login_ui()  
                else:
                    show_error_and_return_to_login("Invalid PIN")

            CURRENT_USER[0] = username
            prompt_for_pin(after_pin)

        forget_password_mfa_prompt(username, login_frame, after_mfa)

    show_new_password_window(username, on_new_password_confirmed)

def update_password_file(username, new_password):
    updated = False
    with open(USER_CREDENTIALS_FILE, "r") as f:
        lines = f.readlines()

    with open(USER_CREDENTIALS_FILE, "w") as f:
        for line in lines:
            line = line.strip()
            if not line or ',' not in line:
                f.write(line + '\n')
                continue

            user, pwd = line.split(",", 1)
            user = user.strip()
            if user == username:
                f.write(f"{user},{new_password}\n")
                updated = True
            else:
                f.write(f"{user},{pwd}\n")

forgot_password_btn = ctk.CTkButton(
    login_frame,
    text="Forgot Password?",
    fg_color="transparent",
    text_color="blue",
    hover_color="#e6e6ff",
    font=ctk.CTkFont(size=14, underline=True),
    corner_radius=0,
    command=lambda: start_forgot_password_flow(login_user_entry.get().strip())
)
forgot_password_btn.place(relx=0.5, rely=0.62, anchor="center")

def forget_password_mfa_prompt(username, parent_frame, on_success):
    for widget in parent_frame.winfo_children():
        widget.destroy()
    parent_frame.configure(fg_color="white")

    files = get_user_files(username)
    mfa_file = files['CREDENTIALS_FILE'].replace('_credentials.txt', '_mfa.txt')
    if not os.path.exists(mfa_file):
        on_success()
        return
    with open(mfa_file, 'r') as f:
        question = f.readline().strip()
        correct_answer = f.readline().strip()

    mfa_bg = ctk.CTkImage(
        light_image=Image.open("Image Files\MFA.png"),
        size=(600, 750)
    )
    mfa_bg_label = ctk.CTkLabel(parent_frame, image=mfa_bg, text="")
    mfa_bg_label.place(relx=0.5, rely=0.5, anchor="center")

    mfa_question = ctk.CTkLabel(parent_frame, text=question,
                                font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=22, weight="bold"),
                                text_color="black")
    mfa_question.place(relx=0.5, rely=0.51, anchor="center")

    answer_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Answer",
                                placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9",
                                width=300, height=50,
                                font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20))
    answer_entry.place(relx=0.5, rely=0.58, anchor="center")

    mfa_error = ctk.CTkLabel(parent_frame, text="", text_color="red")
    mfa_error.place(relx=0.5, rely=0.64, anchor="center")

    def check_answer():
        answer = answer_entry.get().strip()
        if answer.lower() == correct_answer.lower():
            mfa_error.configure(text="Correct!", text_color="green")
            parent_frame.after(500, on_success)
        else:
            def show_invalid_mfa_and_return():
                show_message_window("Invalid MFA")
                build_login_ui

            parent_frame.after(500, show_invalid_mfa_and_return)

    fpass_next_btn = ctk.CTkButton(parent_frame, text="NEXT", width=275, height=55,
                              font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                              command=check_answer, text_color="black", fg_color="transparent",
                              border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    fpass_next_btn.place(relx=0.5, rely=0.7, anchor="center")

# ---------- REGISTER PAGE ---------- #
for widget in register_frame.winfo_children():
    widget.destroy()

register_bg = ctk.CTkImage(
    light_image=Image.open("Image Files\Register Page (1).png"),
    size=(600, 750)
)
register_bg_label = ctk.CTkLabel(register_frame, image=register_bg, text="")
register_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

form_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
form_frame.place(relx=0.5, rely=0.275, anchor="n")

reg_user_entry = ctk.CTkEntry(
    form_frame,
    placeholder_text="Username",
    placeholder_text_color="#D9D9D9",
    text_color="black",
    fg_color="#FEFEFE",
    border_color="#D9D9D9",
    border_width=1,
    corner_radius=8,
    width=250, 
    height=40,
    font=ctk.CTkFont(size=18)
)
reg_user_entry.pack(pady=8)

reg_pass_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
reg_pass_frame.pack(pady=0)
reg_pass_entry = ctk.CTkEntry(
    reg_pass_frame,
    placeholder_text="Password",
    show="*",
    placeholder_text_color="#D9D9D9",
    text_color="black",
    fg_color="#FEFEFE",
    border_color="#D9D9D9",
    border_width=1,
    corner_radius=8,
    width=250, 
    height=40,
    font=ctk.CTkFont(size=18)
)

reg_pass_entry.pack(side="left", pady=8)
reg_pw_visible = [False]

def toggle_reg_pw():
    if reg_pw_visible[0]:
        reg_pass_entry.configure(show="*")
        reg_eye_btn.configure(image=eye_open_img)
    else:
        reg_pass_entry.configure(show="")
        reg_eye_btn.configure(image=eye_closed_img)
    reg_pw_visible[0] = not reg_pw_visible[0]

reg_eye_btn = ctk.CTkButton(
    reg_pass_frame,
    image=eye_open_img,
    text="",
    width=32,
    height=32,
    fg_color="#FEFEFE",
    hover_color="#FEFEFE",
    command=toggle_reg_pw
)

reg_eye_btn.pack(side="left", padx=0)

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    while True:
        password = ''.join(random.choice(chars) for _ in range(length))
        # Ensure it meets all requirements
        if (any(c.isupper() for c in password) and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)):
            return password

def fill_generated_password():
    pw = generate_password()
    reg_pass_entry.delete(0, ctk.END)
    reg_pass_entry.insert(0, pw)
    reg_confirm_entry.delete(0, ctk.END)
    reg_confirm_entry.insert(0, pw)
    update_password_requirements()

generate_pass_img = ctk.CTkImage(light_image=Image.open("Image Files\Generate-Pass-Icon.png"), size=(32, 32))

gen_pw_btn = ctk.CTkButton(
    reg_pass_frame,
    image=generate_pass_img,
    text="",
    width=40,
    height=40,
    fg_color="transparent",
    border_color="#ffffff",
    border_width=1,
    hover_color="#ffffff",
    corner_radius=6,
    command=fill_generated_password
)
gen_pw_btn.pack(side="left", padx=6)

req_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
req_frame.pack(anchor="w", pady=(0, 8))

length_req = ctk.CTkLabel(req_frame, text="• 6-20 characters", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
length_req.pack(anchor="w", pady=1)

upper_req = ctk.CTkLabel(req_frame, text="• One uppercase letter", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
upper_req.pack(anchor="w", pady=1)

number_req = ctk.CTkLabel(req_frame, text="• One number", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
number_req.pack(anchor="w", pady=1)

special_req = ctk.CTkLabel(req_frame, text="• One special character", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
special_req.pack(anchor="w", pady=1)

def update_password_requirements(event=None):
    password = reg_pass_entry.get()
    unmet = 0

    if 6 <= len(password) <= 20:
        length_req.pack_forget()
    else:
        length_req.pack(anchor="w", pady=1)
        unmet += 1

    if any(c.isupper() for c in password):
        upper_req.pack_forget()
    else:
        upper_req.pack(anchor="w", pady=1)
        unmet += 1

    if any(c.isdigit() for c in password):
        number_req.pack_forget()
    else:
        number_req.pack(anchor="w", pady=1)
        unmet += 1

    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        special_req.pack_forget()
    else:
        special_req.pack(anchor="w", pady=1)
        unmet += 1

    if not req_frame.winfo_ismapped():
        req_frame.pack(anchor="w", pady=(0, 8))

    total_reqs = 4
    min_rely = 0.90 
    max_rely = 0.67 
    rely = min_rely + (max_rely - min_rely) * (unmet / total_reqs)

reg_pass_entry.bind('<KeyRelease>', update_password_requirements)

reg_confirm_entry = ctk.CTkEntry(
    form_frame,
    placeholder_text="Confirm Password",
    show="*",
    placeholder_text_color="#D9D9D9",
    text_color="black",
    fg_color="#FEFEFE",
    border_color="#D9D9D9",
    border_width=1,
    corner_radius=8,
    width=250, 
    height=40,
    font=ctk.CTkFont(size=18)
)
reg_confirm_entry.pack(pady=8, ipadx=4, ipady=4)

reg_error = ctk.CTkLabel(form_frame, text="", text_color="red")
reg_error.pack(pady=(0, 5))

button_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
button_frame.place(relx=0.5, rely=1.0, anchor="s", relwidth=0.7, y=-35)

reg_button = ctk.CTkButton(
    button_frame,
    text="SIGN UP",
    width=300,
    height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
    command=register_user,
    text_color="black",
    fg_color="transparent",         
    border_color="black",
    border_width=2,
    hover_color="#FFF6FA",      
    corner_radius=50
)
reg_button.pack(pady=(0, 10))

back_login_btn = ctk.CTkButton(
    button_frame,
    text="BACK TO LOGIN",
    width=300,
    height=55,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
    command=back_to_login,
    text_color="black",
    fg_color="transparent",
    border_color="black",
    border_width=2,
    hover_color="#FFF6FA",
    corner_radius=50
)
back_login_btn.pack(pady=(0, 10))

# ---------- MAIN FRAME ----------
main_bg = ctk.CTkImage(
    light_image=Image.open("Image Files\Main-Page.png"),
    size=(600, 750)
)
main_bg_label = ctk.CTkLabel(main_frame, image=main_bg, text="")
main_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

border_frame = ctk.CTkFrame(main_frame, fg_color="black", corner_radius=50)
border_frame.place(relx=0.27, rely=0.36, anchor="center")

vault_filter = ctk.CTkOptionMenu(
    border_frame,
    values=["All Vaults", "Login", "Credit Card", "Notes"],
    fg_color="white",
    button_color="white",
    button_hover_color="#FEF5F5",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_text_color="black",
    width=200,
    height=40,
    corner_radius=20,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold")
)
vault_filter.set("All Vaults")
vault_filter.pack(padx=8, pady=8)

add_pass_btn = ctk.CTkButton(
    master=main_frame, 
    text="+ Add Password",
    width=200,
    height=50,
    fg_color="#ff94c2",        
    hover_color="#ff6fa1",    
    text_color="#222",
    font=ctk.CTkFont("Arial", size=20, weight="bold"),
    corner_radius=20,
    border_color="black",    
    border_width=5,           
    command=show_add_password
)
add_pass_btn.place(relx=0.75, rely=0.36, anchor="center")  

# ---------- CREDENTIAL CONTAINER ----------
credentials_container = ctk.CTkFrame(main_frame, fg_color="#ffffff")
credentials_container.place(relx=0.5, rely=0.72, anchor="center", relwidth=0.9, relheight=0.6)  

asterisk_icon = ctk.CTkImage(light_image=Image.open("Image Files\icon1.png"), size=(40, 40))
card_icon = ctk.CTkImage(light_image=Image.open("Image Files\icon2.png"), size=(45, 40))
note_icon = ctk.CTkImage(light_image=Image.open("Image Files\icon3.png"), size=(40, 40))

def refresh_main_credentials():
    for widget in credentials_container.winfo_children():
        widget.destroy()
    username = CURRENT_USER[0]
    files = get_user_files(username)
    if not os.path.exists(files['CREDENTIALS_FILE']):
        no_label = ctk.CTkLabel(credentials_container, text="No credentials found.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)
        return
    with open(files['CREDENTIALS_FILE'], "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        no_label = ctk.CTkLabel(credentials_container, text="No saved credentials.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)
        return
    selected_category = vault_filter.get()
    for idx, line in enumerate(lines):
        parts = line.split("|")
        if len(parts) < 2:
            continue
        category = parts[0]
        if selected_category != "All Vaults" and selected_category != category:
            continue

        card = ctk.CTkFrame(credentials_container, fg_color="white", corner_radius=14, border_width=2, border_color="#bbb")
        card.pack(fill="x", pady=8, padx=2)
        card.pack_propagate(False)
        card.configure(height=70)

        if category == "Login":
            entry_type, email, _ = parts[1:]
            title = entry_type
            subtitle = email
            icon = asterisk_icon
        elif category == "Credit Card":
            card_name, card_number, card_expiry, enc_cvv = parts[1:]
            title = card_name
            subtitle = card_number
            icon = card_icon
        elif category == "Notes":
            title, enc_content = parts[1:]
            subtitle = "Hidden Note"
            icon = note_icon
        else:
            title = category
            subtitle = ""
            icon = ""

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=16, pady=8)
        title_label = ctk.CTkLabel(left, text=title, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), text_color="#111")
        title_label.pack(anchor="w")
        subtitle_label = ctk.CTkLabel(left, text=subtitle, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=13), text_color="#444")
        subtitle_label.pack(anchor="w")
        icon_label = ctk.CTkLabel(card, image=icon, text="", fg_color="transparent")
        icon_label.pack(side="right", padx=18)

        card.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        left.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        title_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        subtitle_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        icon_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))

        vault_filter.configure(command=lambda x: refresh_main_credentials())

# ---------- LOGOUT BUTTON ----------
logout_btn_frame = ctk.CTkFrame(main_frame, fg_color="#FFFFFF", width=100, height=70)
logout_btn_frame.place(relx=.97, rely=1, anchor="se", x=-10, y=-10)

logout_img = ctk.CTkImage(Image.open("Image Files/logoutbtn.png"), size=(41, 43))

logout_btn = ctk.CTkButton(
    logout_btn_frame,
    image=logout_img,
    text="",
    width=25, height=43,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"),
    command=logout, fg_color="transparent", hover_color="#FEF5F5", corner_radius=50
)
logout_btn.place(relx=1, rely=1, anchor="se", x=-10, y=-10)

# ---------- ADD PASSWORD PAGE ---------- #
add_bg = ctk.CTkImage(
    light_image=Image.open("Image Files\Add-Paswrod.png"),
    size=(600, 750)
)
add_bg_label = ctk.CTkLabel(add_frame, image=add_bg, text="", fg_color="#FFFFFF")
add_bg_label.place(relx=0.5, rely=0.5, anchor="center")

fields_frame = ctk.CTkFrame(add_frame, fg_color="#FFFFFF", width=400, height=400)
fields_frame.place(relx=0.5, rely=0.5, anchor="center")

login_fields = ctk.CTkFrame(fields_frame, fg_color="#FFFFFF")
type_entry = ctk.CTkEntry(login_fields, placeholder_text="Type", fg_color="#f0f0f0", width=300, height=50, text_color="black", font=ctk.CTkFont(size=20))
type_entry.pack(pady=(10,5), fill="x", padx=20)

email_entry = ctk.CTkEntry(login_fields, placeholder_text="Email/Username", fg_color="#f0f0f0", width=300, height=50, text_color="black", font=ctk.CTkFont(size=20))
email_entry.pack(pady=5, fill="x", padx=20)

password_entry = ctk.CTkEntry(login_fields, placeholder_text="Password", show="*", fg_color="#f0f0f0", width=300, height=50, text_color="black", font=ctk.CTkFont(size=20))
password_entry.pack(pady=5, fill="x", padx=20)

card_fields = ctk.CTkFrame(fields_frame, fg_color="#FFFFFF")
card_name_entry = ctk.CTkEntry(card_fields, placeholder_text="Name on Card", fg_color="#f0f0f0", width=300, height=45, text_color="black", font=ctk.CTkFont(size=20))
card_name_entry.pack(pady=(10,5), fill="x", padx=20)

card_number_entry = ctk.CTkEntry(card_fields, placeholder_text="Card Number", fg_color="#f0f0f0", width=300, height=45, text_color="black", font=ctk.CTkFont(size=20))
card_number_entry.pack(pady=5, fill="x", padx=20)

card_expiry_entry = ctk.CTkEntry(card_fields, placeholder_text="Expiry Date (MM/YY)", fg_color="#f0f0f0", width=300, text_color="black", height=45, font=ctk.CTkFont(size=20))
card_expiry_entry.pack(pady=5, fill="x", padx=20)

card_cvv_entry = ctk.CTkEntry(card_fields, placeholder_text="CVV", show="*", fg_color="#f0f0f0", width=300, height=45, text_color="black", font=ctk.CTkFont(size=20))
card_cvv_entry.pack(pady=5, fill="x", padx=20)

add_card_number_label = ctk.CTkLabel(card_fields, text="", text_color="red", fg_color="#FFFFFF")
add_card_number_label.pack(pady=(10, 2))

add_card_error_label = ctk.CTkLabel(card_fields, text="", text_color="red", fg_color="#FFFFFF")
add_card_error_label.pack(pady=(2, 10))

def update_add_card_type(event=None):
    number = card_number_entry.get()
    if number.startswith("4"):
        add_card_number_label.configure(text="Visa")
    elif number.startswith("5") or number.startswith("2"):
        add_card_number_label.configure(text="Mastercard")
    elif number:
        add_card_number_label.configure(text="Unknown")
    else:
        add_card_number_label.configure(text="")

card_number_entry.bind('<KeyRelease>', update_add_card_type)

notes_fields = ctk.CTkFrame(fields_frame, fg_color="#FFFFFF")
notes_title_entry = ctk.CTkEntry(notes_fields, placeholder_text="Title", fg_color="#f0f0f0", width=300, height=45, text_color="black", font=ctk.CTkFont(size=20))
notes_title_entry.pack(pady=(10, 5), fill="x", padx=20)

notes_content = ctk.CTkTextbox(notes_fields, width=400, height=180, text_color="black", fg_color="#f0f0f0")
notes_content.pack(pady=(5, 15), padx=20)

def switch_category_fields(choice):
    login_fields.place_forget()
    card_fields.place_forget()
    notes_fields.place_forget()
    if choice == "Login":
        login_fields.place(relx=0.5, rely=0.23, anchor="n")
    elif choice == "Credit Card":
        card_fields.place(relx=0.5, rely=0.2, anchor="n")
    elif choice == "Notes":
        notes_fields.place(relx=0.5, rely=0.2, anchor="n")

category_border_frame = ctk.CTkFrame(fields_frame, fg_color="black", corner_radius=50)
category_border_frame.place(relx=0.5, rely=0.05, anchor="n")

category_entry = ctk.CTkOptionMenu(
    category_border_frame,
    values=["Login", "Credit Card", "Notes"],
    command=switch_category_fields,
    fg_color="white",
    button_color="white",
    button_hover_color="#FEF5F5",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_text_color="black",
    width=260,
    height=40,
    corner_radius=20,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold")
)
category_entry.set("Login")
category_entry.pack(padx=8, pady=8)

add_save_btn = ctk.CTkButton(
    fields_frame,
    text="Save",
    width=175,
    height=55,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"),
    command=save_credentials,
    text_color="black",
    fg_color="transparent",
    border_color="black",
    border_width=2,
    hover_color="#FEF5F5",
    corner_radius=50
)
add_save_btn.place(relx=0.25, rely=0.92, anchor="center") 

add_back_btn = ctk.CTkButton(
    fields_frame,
    text="Back",
    width=175,
    height=55,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"),
    command=show_main,
    text_color="black",
    fg_color="transparent",
    border_color="black",
    border_width=2,
    hover_color="#FEF5F5",
    corner_radius=50
)
add_back_btn.place(relx=0.73, rely=0.92, anchor="center")

# ---------- VIEW PASSWORD PAGE ---------- #
detail_bg = ctk.CTkImage(
    light_image=Image.open("Image Files\View-Vault.png"),
    size=(600, 750)
)
detail_bg_label = ctk.CTkLabel(details_frame, image=detail_bg, text="", fg_color="#FFFFFF")
detail_bg_label.place(relx=0.5, rely=0.5, anchor="center")

show_pw_var = ctk.BooleanVar(value=False)

custom_font_large = ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold")
custom_font_medium = ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20)
custom_font_button = ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18, weight="bold")

details_title_label = ctk.CTkLabel(
    details_frame,
    text="",
    font=custom_font_large,
    text_color="black"
)
details_title_label.pack(pady=(170, 0))  

details_subtitle_label = ctk.CTkLabel(
    details_frame,
    text="",
    font=custom_font_medium,
    text_color="#888888"
)
details_subtitle_label.pack(pady=(5, 0))  

details_text = ctk.CTkTextbox(
    details_frame,
    width=400,
    height=160,
    font=custom_font_medium,
    fg_color="black",
    text_color="white",
    wrap="none",
)
details_text.pack(pady=(50, 0))  

pw_toggle = ctk.CTkSwitch(
    details_frame,
    text="Show Passwords",
    variable=show_pw_var, border_color="black", border_width=2,
    font=ctk.CTkFont(size=18, weight="bold")
)
pw_toggle.place(relx=0.5, rely=0.7, anchor="center")

btn_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
btn_frame.place(relx=0.56, rely=0.8, anchor="center")

original_line = []
edit_btn = ctk.CTkButton(
    btn_frame, text="🖉  Edit", width=140, height=60,
    font=custom_font_button,  
    text_color="black", fg_color="transparent",
    border_color="black", border_width=2, hover_color="#FEF5F5",
    corner_radius=50, command=lambda: edit_credential_in_page(original_line)
)
edit_btn.pack(side="left", padx=8)

delete_btn = ctk.CTkButton(
    btn_frame, text="🗑️  Delete", width=140, height=60,
    font=custom_font_button,  
    text_color="black", fg_color="transparent",
    border_color="#d32f2f", border_width=2, hover_color="#FFE5E5",
    corner_radius=50
)

delete_btn.pack(side="left", padx=8)

view_back_btn = ctk.CTkButton(
    details_frame, text="<", width=50, height=60,
    font=custom_font_button, text_color="black", fg_color="transparent",
    border_color="black", border_width=2, hover_color="#FEF5F5",
    corner_radius=50, command=show_main
)
view_back_btn.place(relx=0.2, rely=0.8, anchor="center")

current_cred = {'parts': None, 'category': None, 'idx': None, 'lines': None}

def update_details_text():
    details_text.configure(state="normal")
    details_text.delete("1.0", ctk.END)

    parts = current_cred['parts']
    category = current_cred['category']
    username = CURRENT_USER[0]
    show_pw = show_pw_var.get()

    if not parts or not category:
        details_title_label.configure(text="")
        details_subtitle_label.configure(text="")
        details_text.insert("1.0", "No credential selected.")
        details_text.configure(state="disabled")
        return

    try:
        if category == "Login":

            entry_type, email, enc_password = parts[1:]
            password = decrypt_data(enc_password, username) if show_pw else ""

            details_title_label.configure(text=entry_type)
            details_subtitle_label.configure(text=category)

            display_text = (
                "\n"
                " Account:      " + entry_type + "\n"
                " Username:   " + email + "\n"
                " Password:   " + password + "\n"
            )

        elif category == "Credit Card":

            card_name, card_number, _, enc_cvv = parts[1:]
            cvv = decrypt_data(enc_cvv, username) if show_pw else "*"

            details_title_label.configure(text=card_name)
            details_subtitle_label.configure(text="CREDIT CARD")


            display_text = (
                "\n"
                " Cardholder:     " +  card_name + "\n"
                " Card Number:  " + card_number + "\n"
                " CVV/Passkey:  " + cvv + "\n"
            )

        elif category == "Notes":

            title, enc_content = parts[1:]
            content = decrypt_data(enc_content, username) if show_pw else "*"

            details_title_label.configure(text=title)
            details_subtitle_label.configure(text="NOTES")

            display_text = (
                "\n"
                " Title          :  " + title + "\n"
                " Content        :  " + content + "\n"
            )

        else:
            details_title_label.configure(text="Unknown")
            details_subtitle_label.configure(text="")
            display_text = "Unknown credential format"

    except Exception as e:
        details_title_label.configure(text="Error")
        details_subtitle_label.configure(text="")
        display_text = f"[Error decrypting data: {str(e)}]"

    details_text.insert("1.0", display_text)
    details_text.configure(state="disabled")

def on_pw_toggle():
    if show_pw_var.get():
        pw_toggle.configure(state="disabled")
        def after_pin(success):
            if success:
                show_pw_var.set(True)
            else:
                show_pw_var.set(False)
            update_details_text()
            pw_toggle.configure(state="normal")
        request_pin(callback=after_pin)
    else:
        update_details_text()

pw_toggle.configure(command=on_pw_toggle)

update_details_text()

def format_credential(category, parts, username, masked=True, for_listbox=False):
    try:
        if category == "Login":
            entry_type, email, enc_password = parts
            password = decrypt_data(enc_password, username) if not masked else "*****"
            if for_listbox:
                return f"Type: {entry_type} | Email: {email} | Password: {password}"
            else:
                return f"Type:     {entry_type}\nEmail:    {email}\nPassword: {password}"

        elif category == "Credit Card":
            card_name, card_number, card_expiry, enc_cvv = parts
            cvv = decrypt_data(enc_cvv, username) if not masked else "*****"
            if for_listbox:
                return f"Name: {card_name} | Number: {card_number} | Expiry: {card_expiry} | CVV: {cvv}"
            else:
                return (f"Name:     {card_name}\n"
                        f"Number:   {card_number}\n"
                        f"Expiry:   {card_expiry}\n"
                        f"CVV:      {cvv}")

        elif category == "Notes":
            title, enc_content = parts
            content = decrypt_data(enc_content, username) if not masked else "*****"
            if for_listbox:
                return f"Title: {title} | Content: {content}"
            else:
                return f"Title:    {title}\nContent:  {content}"

    except Exception:
        return "[Error decrypting]"

def show_credential_details(idx, parts, category, lines):
    current_cred['parts'] = parts
    current_cred['category'] = category
    current_cred['idx'] = idx
    current_cred['lines'] = lines
    update_details_text()

    def edit_action():
        details_frame.pack_forget()
        original_line = "|".join(parts)
        edit_credential_in_page(parts, original_line)

    def delete_action():
        del lines[idx]
        files = get_user_files(CURRENT_USER[0])
        with open(files['CREDENTIALS_FILE'], "w") as f:
            for l in lines:
                f.write(l + "\n")
        details_frame.pack_forget()
        show_main()

    def back_action():
        details_frame.pack_forget()
        show_main()

    edit_btn.configure(command=edit_action)
    delete_btn.configure(command=delete_action)

    main_frame.pack_forget()
    details_frame.pack(fill="both", expand=True)


def create_fields(parent):
    login_fields = ctk.CTkFrame(parent, fg_color="#FFFFFF")
    
    type_entry = ctk.CTkEntry(login_fields, placeholder_text="Type", fg_color="#f0f0f0", width=300, height=50,
                               text_color="black", font=ctk.CTkFont(size=20))
    type_entry.pack(pady=(10, 5), fill="x", padx=20)

    email_entry = ctk.CTkEntry(login_fields, placeholder_text="Email/Username", fg_color="#f0f0f0", width=300, height=50,
                                text_color="black", font=ctk.CTkFont(size=20))
    email_entry.pack(pady=5, fill="x", padx=20)

    password_entry = ctk.CTkEntry(login_fields, placeholder_text="Password", show="*", fg_color="#f0f0f0", width=300,
                                   height=50, text_color="black", font=ctk.CTkFont(size=20))
    password_entry.pack(pady=5, fill="x", padx=20)

    card_fields = ctk.CTkFrame(parent, fg_color="#FFFFFF")

    card_name_entry = ctk.CTkEntry(card_fields, placeholder_text="Name on Card", fg_color="#f0f0f0", width=300, height=45,
                                    text_color="black", font=ctk.CTkFont(size=20))
    card_name_entry.pack(pady=(10, 5), fill="x", padx=20)

    card_number_entry = ctk.CTkEntry(card_fields, placeholder_text="Card Number", fg_color="#f0f0f0", width=300,
                                      height=45, text_color="black", font=ctk.CTkFont(size=20))
    card_number_entry.pack(pady=5, fill="x", padx=20)

    card_expiry_entry = ctk.CTkEntry(card_fields, placeholder_text="Expiry Date (MM/YY)", fg_color="#f0f0f0", width=300,
                                      height=45, text_color="black", font=ctk.CTkFont(size=20))
    card_expiry_entry.pack(pady=5, fill="x", padx=20)

    card_cvv_entry = ctk.CTkEntry(card_fields, placeholder_text="CVV", show="*", fg_color="#f0f0f0", width=300, height=45,
                                   text_color="black", font=ctk.CTkFont(size=20))
    card_cvv_entry.pack(pady=5, fill="x", padx=20)

    notes_fields = ctk.CTkFrame(parent, fg_color="#FFFFFF")

    notes_title_entry = ctk.CTkEntry(notes_fields, placeholder_text="Title", fg_color="#f0f0f0", width=300, height=45,
                                      text_color="black", font=ctk.CTkFont(size=20))
    notes_title_entry.pack(pady=(10, 5), fill="x", padx=20)

    notes_content = ctk.CTkTextbox(notes_fields, width=400, height=180, text_color="black", fg_color="#f0f0f0")
    notes_content.pack(pady=(5, 15), padx=20)

    return {
        "login": {
            "frame": login_fields,
            "type": type_entry,
            "email": email_entry,
            "password": password_entry
        },
        "card": {
            "frame": card_fields,
            "name": card_name_entry,
            "number": card_number_entry,
            "expiry": card_expiry_entry,
            "cvv": card_cvv_entry
        },
        "notes": {
            "frame": notes_fields,
            "title": notes_title_entry,
            "content": notes_content
        }
    }

def prefill_fields(fields_dict, line):
    parts = line.strip().split('|')
    category = parts[0]
    if category == "Login":
        fields_dict["login"]["type"].delete(0, "end")
        fields_dict["login"]["type"].insert(0, parts[1])
        fields_dict["login"]["email"].delete(0, "end")
        fields_dict["login"]["email"].insert(0, parts[2])
        fields_dict["login"]["password"].delete(0, "end")
        fields_dict["login"]["password"].insert(0, parts[3])
        switch_category_fields("Login")
    elif category == "Credit Card":
        fields_dict["card"]["name"].delete(0, "end")
        fields_dict["card"]["name"].insert(0, parts[1])
        fields_dict["card"]["number"].delete(0, "end")
        fields_dict["card"]["number"].insert(0, parts[2])
        fields_dict["card"]["expiry"].delete(0, "end")
        fields_dict["card"]["expiry"].insert(0, parts[3])
        fields_dict["card"]["cvv"].delete(0, "end")
        fields_dict["card"]["cvv"].insert(0, parts[4])
        switch_category_fields("Credit Card")
    elif category == "Notes":
        fields_dict["notes"]["title"].delete(0, "end")
        fields_dict["notes"]["title"].insert(0, parts[1])
        fields_dict["notes"]["content"].delete("1.0", "end")
        fields_dict["notes"]["content"].insert("1.0", parts[2])
        switch_category_fields("Notes")

def build_line_from_fields(fields_dict):
    category = category_entry.get()
    if category == "Login":
        return "|".join([
            "Login",
            fields_dict["login"]["type"].get(),
            fields_dict["login"]["email"].get(),
            fields_dict["login"]["password"].get()
        ])
    elif category == "Credit Card":
        return "|".join([
            "Credit Card",
            fields_dict["card"]["name"].get(),
            fields_dict["card"]["number"].get(),
            fields_dict["card"]["expiry"].get(),
            fields_dict["card"]["cvv"].get()
        ])
    elif category == "Notes":
        return "|".join([
            "Notes",
            fields_dict["notes"]["title"].get(),
            fields_dict["notes"]["content"].get("1.0", "end").strip()
        ])

def build_edit_page(edit_frame, selected_line, on_save_callback, on_back_callback):
    for widget in edit_frame.winfo_children():
        widget.destroy()

    edit_bg = ctk.CTkImage(light_image=Image.open("Image Files\Edit-Password.png"), size=(600, 750))
    edit_bg_label = ctk.CTkLabel(edit_frame, image=edit_bg, text="", fg_color="#FFFFFF")
    edit_bg_label.place(relx=0.5, rely=0.5, anchor="center")

    form_frame = ctk.CTkFrame(edit_frame, fg_color="transparent")
    form_frame.place(relx=0.5, rely=0.32, anchor="n")

    label_font = ctk.CTkFont(size=18, weight="bold")
    entry_font = ctk.CTkFont(size=20)

    platform_label = ctk.CTkLabel(form_frame, text="Platform:", font=label_font, text_color="black")
    platform_entry = ctk.CTkEntry(form_frame, width=300, height=50, fg_color="#f0f0f0", text_color="black", font=entry_font)

    username_label = ctk.CTkLabel(form_frame, text="Username:", font=label_font, text_color="black")
    username_entry = ctk.CTkEntry(form_frame, width=300, height=50, fg_color="#f0f0f0", text_color="black", font=entry_font)

    password_label = ctk.CTkLabel(form_frame, text="Password:", font=label_font, text_color="black")
    password_entry = ctk.CTkEntry(form_frame, width=300, height=50, show="*", fg_color="#f0f0f0", text_color="black", font=entry_font)

    card_name_label = ctk.CTkLabel(form_frame, text="Name on Card:", font=label_font, text_color="black")
    card_name_entry = ctk.CTkEntry(form_frame, width=300, height=45, fg_color="#f0f0f0", text_color="black", font=entry_font)

    card_number_label = ctk.CTkLabel(form_frame, text="Card Number:", font=label_font, text_color="black")
    card_number_entry = ctk.CTkEntry(form_frame, width=300, height=45, fg_color="#f0f0f0", text_color="black", font=entry_font)

    card_expiry_label = ctk.CTkLabel(form_frame, text="Expiry Date:", font=label_font, text_color="black")
    card_expiry_entry = ctk.CTkEntry(form_frame, width=300, height=45, fg_color="#f0f0f0", text_color="black", font=entry_font)

    card_cvv_label = ctk.CTkLabel(form_frame, text="CVV:", font=label_font, text_color="black")
    card_cvv_entry = ctk.CTkEntry(form_frame, width=300, height=45, show="*", fg_color="#f0f0f0", text_color="black", font=entry_font)

    notes_label = ctk.CTkLabel(form_frame, text="Notes:", font=label_font, text_color="black")
    notes_textbox = ctk.CTkTextbox(form_frame, width=300, height=100, fg_color="#f0f0f0", text_color="black", font=ctk.CTkFont(size=18))

    def clear_category_fields():
        for w in [
            platform_label, platform_entry,
            username_label, username_entry,
            password_label, password_entry,
            card_name_label, card_name_entry,
            card_number_label, card_number_entry,
            card_expiry_label, card_expiry_entry,
            card_cvv_label, card_cvv_entry,
            notes_label, notes_textbox,
        ]:
            w.pack_forget()

    def switch_category_fields(event=None):
        clear_category_fields()
        cat = category_combobox.get()
        if cat == "Login":
            platform_label.pack(pady=(10, 0))
            platform_entry.pack(pady=(0, 10))
            username_label.pack()
            username_entry.pack(pady=(0, 10))
            password_label.pack()
            password_entry.pack(pady=(0, 10))
        elif cat == "Credit Card":
            card_name_label.pack(pady=(10, 0))
            card_name_entry.pack(pady=(0, 10))
            card_number_label.pack()
            card_number_entry.pack(pady=(0, 10))
            card_expiry_label.pack()
            card_expiry_entry.pack(pady=(0, 10))
            card_cvv_label.pack()
            card_cvv_entry.pack(pady=(0, 10))
        elif cat == "Notes":
            notes_label.pack(pady=(10, 0))
            notes_textbox.pack(pady=(0, 10))

    category_border_frame = ctk.CTkFrame(edit_frame, fg_color="black", corner_radius=50)
    category_border_frame.place(relx=0.5, rely=0.25, anchor="n")

    category_combobox = ctk.CTkOptionMenu(
        category_border_frame,
        values=["Login", "Credit Card", "Notes"],
        command=switch_category_fields,
        fg_color="white",
        button_color="white",
        button_hover_color="#FEF5F5",
        text_color="black",
        dropdown_fg_color="white",
        dropdown_text_color="black",
        width=260,
        height=40,
        corner_radius=20,
        font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold")
    )
    category_combobox.set("Login")
    category_combobox.pack(padx=8, pady=8)

    parts = []
    if selected_line:
        username = CURRENT_USER[0]
        parts = selected_line.strip().split("|")
        category = parts[0]
        category_combobox.set(category)
        switch_category_fields()

        if category == "Login":
            platform_entry.insert(0, parts[1])
            username_entry.insert(0, parts[2])
            password_entry.insert(0, decrypt_data(parts[3], username))
        elif category == "Credit Card":
            card_name_entry.insert(0, parts[1])
            card_number_entry.insert(0, parts[2])
            card_expiry_entry.insert(0, parts[3])
            card_cvv_entry.insert(0, decrypt_data(parts[4], username))
        elif category == "Notes":
            notes_textbox.insert("1.0", decrypt_data(parts[2], username))
    else:
        category_combobox.set("Login")
        switch_category_fields()

    pin_verified = False

    def save_callback():
        nonlocal pin_verified
        username = CURRENT_USER[0]
        cat = category_combobox.get()

        def on_pin_verified(success):
            nonlocal pin_verified
            if not success:
                messagebox.showerror("Error", "PIN verification failed.")
                return

            pin_verified = True

            if cat == "Login":
                platform = platform_entry.get()
                user = username_entry.get()
                password = password_entry.get()
                enc_password = encrypt_data(password, username)
                new_line = f"{cat}|{platform}|{user}|{enc_password}"
            elif cat == "Credit Card":
                name = card_name_entry.get()
                number = card_number_entry.get()
                expiry = card_expiry_entry.get()
                cvv = card_cvv_entry.get()
                enc_cvv = encrypt_data(cvv, username)
                new_line = f"{cat}|{name}|{number}|{expiry}|{enc_cvv}"
            elif cat == "Notes":
                content = notes_textbox.get("1.0", ctk.END).strip()
                title = parts[1] if parts else "Untitled"
                enc_content = encrypt_data(content, username)
                new_line = f"{cat}|{title}|{enc_content}"
            else:
                messagebox.showerror("Error", "Unknown category.")
                return

            old_line = selected_line if selected_line else None
            on_save_callback(old_line, new_line)

        if pin_verified:
            on_pin_verified(True)
        else:
            request_pin(on_pin_verified)

    btn_frame = ctk.CTkFrame(edit_frame, fg_color="transparent")
    btn_frame.pack(pady=(600, 0)) 

    save_btn = ctk.CTkButton(btn_frame, text="SAVE", width=130, height=50,
                         font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18),
                         command=save_callback, text_color="black", fg_color="transparent",
                         border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    save_btn.pack(side="left", padx=(0, 50))  

    cancel_btn = ctk.CTkButton(btn_frame, text="CANCEL", width=130, height=50,
                           font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18),
                           command=on_back_callback, text_color="black", fg_color="transparent",
                           border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    cancel_btn.pack(side="left")

    return {
        "category_combobox": category_combobox,
        "platform_entry": platform_entry,
        "username_entry": username_entry,
        "password_entry": password_entry,
        "card_name_entry": card_name_entry,
        "card_number_entry": card_number_entry,
        "card_expiry_entry": card_expiry_entry,
        "card_cvv_entry": card_cvv_entry,
        "notes_textbox": notes_textbox,
        "switch_category_fields": switch_category_fields,
    }

def on_save(old_line, new_line):
    global credentials_lines
    try:
        idx = credentials_lines.index(old_line)
        credentials_lines[idx] = new_line
    except ValueError:
        credentials_lines.append(new_line)

    update_credentials_file()
    messagebox.showinfo("Success", "Credential updated.")
    show_main()

def migrate_old_credentials_file(username):
    old_path = f"{username}_credentials.txt"
    new_path = f"Database/{username}_credentials.txt"
    if os.path.exists(old_path) and not os.path.exists(new_path):
        os.makedirs(os.path.dirname(new_path), exist_ok=True)
        shutil.move(old_path, new_path)

search_frame = ctk.CTkFrame(main_frame, fg_color="#FFFFFF")
search_frame.place(relx=0.5, rely=0.25, anchor="center", relwidth=0.85) 
search_icon_img = ctk.CTkImage(Image.open("Image Files/search_icon.png"), size=(24, 24))
search_entry = ctk.CTkEntry(
    search_frame,
    placeholder_text="Search Vault",
    placeholder_text_color="#B0B0B0",
    fg_color="#FAFAFA",
    text_color="black",
    border_color="#E0E0E0",
    border_width=2,
    corner_radius=24,
    font=ctk.CTkFont(size=18),
    width=420,
    height=44
)

search_entry.pack(side="left", fill="both", expand=True, padx=(8,0), pady=2)
search_icon_label = ctk.CTkLabel(search_frame, image=search_icon_img, text="", fg_color="#FAFAFA")
search_icon_label.pack(side="right", padx=(0,12), pady=2)

def search_credentials(event=None):
    search_term = search_entry.get().lower().strip()
    for widget in credentials_container.winfo_children():
        widget.destroy()
    
    username = CURRENT_USER[0]
    files = get_user_files(username)
    if not os.path.exists(files['CREDENTIALS_FILE']):
        no_label = ctk.CTkLabel(credentials_container, text="No credentials found.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)
        return
        
    with open(files['CREDENTIALS_FILE'], "r") as f:
        lines = [line.strip() for line in f if line.strip()]
        
    if not lines:
        no_label = ctk.CTkLabel(credentials_container, text="No saved credentials.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)
        return
        
    selected_category = vault_filter.get()
    found_any = False
    
    for idx, line in enumerate(lines):
        parts = line.split("|")
        if len(parts) < 2:
            continue
            
        category = parts[0]
        if selected_category != "All Vaults" and selected_category != category:
            continue
            
        if category == "Login":
            name = parts[1] 
        elif category == "Credit Card":
            name = parts[1]  
        elif category == "Notes":
            name = parts[1]  
        else:
            continue

        if search_term in name.lower():
            found_any = True
            card = ctk.CTkFrame(credentials_container, fg_color="white", corner_radius=14, border_width=2, border_color="#bbb")
            card.pack(fill="x", pady=8, padx=2)
            card.pack_propagate(False)
            card.configure(height=70)
            
            if category == "Login":
                entry_type, email, _ = parts[1:]
                title = entry_type
                subtitle = email
                icon = asterisk_icon
            elif category == "Credit Card":
                card_name, card_number, card_expiry, enc_cvv = parts[1:]
                title = card_name
                subtitle = card_number
                icon = card_icon
            elif category == "Notes":
                title, enc_content = parts[1:]
                subtitle = "Hidden Note"
                icon = note_icon
            else:
                title = category
                subtitle = ""
                icon = ""
                
            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=16, pady=8)
            title_label = ctk.CTkLabel(left, text=title, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), text_color="#111")
            title_label.pack(anchor="w")
            subtitle_label = ctk.CTkLabel(left, text=subtitle, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=13), text_color="#444")
            subtitle_label.pack(anchor="w")
            icon_label = ctk.CTkLabel(card, image=icon, text="", fg_color="transparent")
            icon_label.pack(side="right", padx=18)
            
            card.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            left.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            title_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            subtitle_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            icon_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
    
    if not found_any:
        no_label = ctk.CTkLabel(credentials_container, text="No matching credentials found.", text_color="gray", fg_color="transparent")
        no_label.pack(pady=10)

search_entry.bind('<KeyRelease>', search_credentials)

def refresh_main_credentials():
    if search_entry.get().strip():
        search_credentials()
    else:
        for widget in credentials_container.winfo_children():
            widget.destroy()
        username = CURRENT_USER[0]
        files = get_user_files(username)
        if not os.path.exists(files['CREDENTIALS_FILE']):
            no_label = ctk.CTkLabel(credentials_container, text="No credentials found.", text_color="gray", fg_color="transparent")
            no_label.pack(pady=10)
            return
        with open(files['CREDENTIALS_FILE'], "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            no_label = ctk.CTkLabel(credentials_container, text="No saved credentials.", text_color="gray", fg_color="transparent")
            no_label.pack(pady=10)
            return
        selected_category = vault_filter.get()
        for idx, line in enumerate(lines):
            parts = line.split("|")
            if len(parts) < 2:
                continue
            category = parts[0]
            if selected_category != "All Vaults" and selected_category != category:
                continue

            card = ctk.CTkFrame(credentials_container, fg_color="white", corner_radius=14, border_width=2, border_color="#bbb")
            card.pack(fill="x", pady=8, padx=2)
            card.pack_propagate(False)
            card.configure(height=70)

            if category == "Login":
                entry_type, email, _ = parts[1:]
                title = entry_type
                subtitle = email
                icon = asterisk_icon
            elif category == "Credit Card":
                card_name, card_number, card_expiry, enc_cvv = parts[1:]
                title = card_name
                subtitle = card_number
                icon = card_icon
            elif category == "Notes":
                title, enc_content = parts[1:]
                subtitle = "Hidden Note"
                icon = note_icon
            else:
                title = category
                subtitle = ""
                icon = ""

            left = ctk.CTkFrame(card, fg_color="transparent")
            left.pack(side="left", fill="both", expand=True, padx=16, pady=8)
            title_label = ctk.CTkLabel(left, text=title, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), text_color="#111")
            title_label.pack(anchor="w")
            subtitle_label = ctk.CTkLabel(left, text=subtitle, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=13), text_color="#444")
            subtitle_label.pack(anchor="w")
            icon_label = ctk.CTkLabel(card, image=icon, text="", fg_color="transparent")
            icon_label.pack(side="right", padx=18)

            card.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            left.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            title_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            subtitle_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
            icon_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))

vault_filter.configure(command=lambda x: refresh_main_credentials())

app.mainloop()
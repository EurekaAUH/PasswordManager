# IMPORTS
import customtkinter as ctk
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

# Global variables for card labels
card_number_label = None
card_error_label = None

eye_open_img = ctk.CTkImage(Image.open("PasswordManager\Image Files\SeePassword-Icon.png"), size=(33, 33))
eye_closed_img = ctk.CTkImage(Image.open("PasswordManager\Image Files\Hide-Icon.png"), size=(33, 33))

# KEY FILES 
KEY_FILE = "Database\key.key"
CREDENTIALS_FILE = "Database\savedcredentials.txt"

# USER-SPECIFIC FILES
CURRENT_USER = [None]  # Use a list for mutability in nested functions

def get_user_files(username):
    return {
        'CREDENTIALS_FILE': f"Database\{username}_credentials.txt",
        'PIN_FILE': f"Database\{username}_pin.hash",
        'KEY_FILE': f"Database\{username}_key.key"
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
ctk.set_appearance_mode("dark")





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

# Set all main frames' background color to white
login_frame.configure(fg_color="#FFFFFF")
register_frame.configure(fg_color="#FFFFFF")
main_frame.configure(fg_color="#FFFFFF")
add_frame.configure(fg_color="#FFFFFF")
details_frame.configure(fg_color="#FFFFFF")
view_frame.configure(fg_color="#FFFFFF")
edit_frame.configure(fg_color="#FFFFFF")
opening_frame.configure(fg_color="#FFFFFF")


# ---------- PAGE SWITCHING ---------- #
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    main_frame.pack(fill="both", expand=True, padx=0, pady=0)
    refresh_main_credentials()

def show_add_password():
    # Reset save/back buttons to add mode
    save_btn.configure(text="Save", command=save_credentials)
    back_btn.configure(text="Back", command=show_main)
    main_frame.pack_forget()
    add_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_view_passwords():
    main_frame.pack_forget()
    view_frame.pack(fill="both", expand=True, padx=20, pady=20)
    load_credentials()

def show_register():
    login_frame.pack_forget()
    register_frame.pack(fill="both", expand=True, padx=20, pady=20)

def back_to_login():
    register_frame.pack_forget()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

def show_edit_passwords():
    main_frame.pack_forget()
    edit_frame.pack(fill="both", expand=True, padx=20, pady=20)
    load_credentials()

# ---------- NEWWWWWWW ---------- #
def logout():
    CURRENT_USER[0] = None
    main_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    try:
        login_user_entry.delete(0, ctk.END)
        login_pass_entry.delete(0, ctk.END)
    except Exception:
        pass
    login_error.configure(text="")  
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

    # Validate username length
    if not (6 <= len(username) <= 20):
        login_error.configure(text="Username must be between 6 and 20 characters.")
        return

    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as f:
            for line in f:
                if not line.strip() or "," not in line:
                    continue  # skip empty or malformed lines

                saved_user, saved_pass = line.strip().split(",")

                if saved_user == username and saved_pass == password:
                    # Initialize user files if they don't exist
                    files = get_user_files(username)
                    if not os.path.exists(files['CREDENTIALS_FILE']):
                        open(files['CREDENTIALS_FILE'], 'w').close()
                    if not os.path.exists(files['KEY_FILE']):
                        generate_key(username)

                    login_count = increment_login_count(username)

                    def after_mfa():
                        show_main()

                    if login_count % 3 == 0:
                        show_mfa_verify_prompt_in_frame(username, login_frame, after_mfa)
                    else:
                        show_main()
                    return

    login_error.configure(text="Invalid credentials.")


def register_user():
    username = reg_user_entry.get().strip()
    password = reg_pass_entry.get().strip()
    confirm = reg_confirm_entry.get().strip()

    # Validate username
    username_valid, username_error = validate_username(username)
    if not username_valid:
        reg_error.configure(text=username_error)
        return

    # Validate password (pass username too!)
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
        
        # Create user-specific files
        files = get_user_files(username)
        open(files['CREDENTIALS_FILE'], 'w').close()  # Create empty credentials file
        generate_key(username)  # Generate encryption key for the user
        
        # Save user credentials
        with open(USER_CREDENTIALS_FILE, "a") as f:
            f.write(f"{username},{password}\n")
        
        CURRENT_USER[0] = username
        show_mfa_prompt_in_frame(username, register_frame, back_to_login)




def show_mfa_prompt_in_frame(username, parent_frame, on_success):
    for widget in parent_frame.winfo_children():
        widget.destroy()
    parent_frame.configure(fg_color="white")

    # Load the background image
    mfa_bg = ctk.CTkImage(
        light_image=Image.open("PasswordManager\Image Files\FA.png"),
        size=(600, 750)
    )
    mfa_bg_label = ctk.CTkLabel(parent_frame, image=mfa_bg, text="")
    mfa_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

    # Predefined list of questions
    predefined_questions = [
        "What is your childhood nickname?",
        "What is your favorite color?",
        "What was your dream job as a child?",
        "What is your mother's maiden name?",
        "What was your favorite teacher's name?",
        "What city were you born in?",
        "What is your favorite movie?"
    ]

# Outer frame as border without fixed size
    parent_bg = parent_frame.cget("fg_color")  


    border_frame = ctk.CTkFrame(parent_frame)
    border_frame.place(relx=0.5, rely=0.55, anchor="center")

# Dropdown for question inside the border frame with padding for border effect
    question_dropdown = ctk.CTkOptionMenu(border_frame, values=predefined_questions,
                                      fg_color="white", button_color="white", button_hover_color="#FEF5F5",
                                      text_color="black", dropdown_fg_color="white", dropdown_text_color="black",
                                      width=275, height=55, corner_radius=70, 
                                      font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=18, weight="bold"))
    question_dropdown.set("Select a question")

# pack with padding to create the border effect
    question_dropdown.pack(padx=4, pady=4)


# Answer entry
    answer_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Answer",
                            placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9",
                            width=300, height=50,
                            font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20))
    answer_entry.place(relx=0.5, rely=0.67, anchor="center")


    # Error/success label
    mfa_error = ctk.CTkLabel(parent_frame, text="", text_color="red")
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
        parent_frame.after(1000, on_success)

    # Save button
    save_btn = ctk.CTkButton(parent_frame, text="SAVE", width=275, height=55,
                         font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                         command=save_mfa, text_color="black", fg_color="transparent",
                         border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    save_btn.place(relx=0.5, rely=0.8, anchor="center")





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

    # Load the background image
    mfa_bg = ctk.CTkImage(
        light_image=Image.open("2FA.png"),
        size=(600, 750)
    )
    mfa_bg_label = ctk.CTkLabel(parent_frame, image=mfa_bg, text="")
    mfa_bg_label.place(relx=0.5, rely=0.5, anchor="center")

    # The user's MFA question (bold)
    mfa_question = ctk.CTkLabel(parent_frame, text=question, fg_color="white",
                                font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=22, weight="bold"),
                                text_color="black")
    mfa_question.place(relx=0.5, rely=0.51, anchor="center")

    # Answer entry
    answer_entry = ctk.CTkEntry(parent_frame, placeholder_text="Enter Answer",
                                placeholder_text_color="#D9D9D9", fg_color="#FEFEFE", text_color="black", border_color="#D9D9D9",
                                width=300, height=50,
                                font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20))
    answer_entry.place(relx=0.5, rely=0.58, anchor="center")

    # Error label
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

    # LOGIN button
    login_btn = ctk.CTkButton(parent_frame, text="LOGIN", width=275, height=55,
                              font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                              command=check_answer, text_color="black", fg_color="transparent",
                              border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    login_btn.place(relx=0.5, rely=0.7, anchor="center")

    # GO BACK button
    back_btn = ctk.CTkButton(parent_frame, text="GO BACK", width=275, height=55,
                             font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
                             command=go_back, text_color="black", fg_color="transparent",
                             border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
    back_btn.place(relx=0.5, rely=0.8, anchor="center")





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

# Flag to toggle password visibility
show_passwords = False  # Flag for password visibility toggle

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

    # Use the centralized request_pin function to handle PIN prompt and registration if needed
    request_pin(on_pin_verified)


# Assuming visibility_switch is created somewhere in your UI setup code:
visibility_switch = ctk.CTkSwitch(
    master=view_frame,
    text="Show Passwords",
    command=toggle_password_visibility
)
visibility_switch.pack(pady=5)



# LOAD CREDENTIALS
def load_credentials():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    listbox.delete(0, ctk.END)

    if not os.path.exists(files['CREDENTIALS_FILE']):
        return

    with open(files['CREDENTIALS_FILE'], "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    grouped = {}
    for line in lines:
        parts = line.split("|")
        if len(parts) >= 2:
            category = parts[0]
            grouped.setdefault(category, []).append(parts[1:])

    selected_category = edit_category_filter.get()
    for category in ["Login", "Credit Card", "Notes"]:
        if selected_category != "All" and category != selected_category:
            continue
        if category in grouped:
            listbox.insert(ctk.END, f"=== {category} ===")
            for parts in grouped[category]:
                text = format_credential(category, parts, username, masked=True, for_listbox=True)
                listbox.insert(ctk.END, text)
            listbox.insert(ctk.END, "")






# DELETE SELECTED CREDENTIAL
def delete_selected():
    selected_indices = listbox.curselection()
    if not selected_indices:
        messagebox.showwarning("No selection", "Please select an entry to delete.")
        return
    index = selected_indices[0]
    listbox.delete(index)
    update_credentials_file()

def edit_selected():
    def after_pin(success):
        if not success:
            return

        selected_indices = listbox.curselection()
        if not selected_indices:
            messagebox.showwarning("No selection", "Please select an entry to edit.")
            return
        index = selected_indices[0]

        # Get the selected text
        selected_text = listbox.get(index)

        # Skip if it's a category header or empty line
        if selected_text.startswith("===") or not selected_text.strip():
            messagebox.showwarning("Invalid Selection", "Please select an actual entry to edit.")
            return

        # Read from file
        username = CURRENT_USER[0]
        files = get_user_files(username)
        if not os.path.exists(files['CREDENTIALS_FILE']):
            messagebox.showerror("Error", "Credentials file not found.")
            return

        with open(files['CREDENTIALS_FILE'], "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        # Find the matching entry
        selected_line = None
        current_category = None

        for line in lines:
            parts = line.split("|")
            if len(parts) >= 2:
                category = parts[0]
                if category in ["Login", "Credit Card", "Notes"]:
                    # Create display text for comparison (masked password/content)
                    if category == "Login":
                        if len(parts) < 4:
                            continue
                        entry_type, email, _ = parts[1:4]
                        display_text = f"Type: {entry_type} | Email: {email} | Password: *****"
                    elif category == "Credit Card":
                        if len(parts) < 5:
                            continue
                        card_name, card_number, card_expiry, _ = parts[1:5]
                        display_text = f"Name: {card_name} | Number: {card_number} | Expiry: {card_expiry} | CVV: *****"
                    elif category == "Notes":
                        if len(parts) < 3:
                            continue
                        title, _ = parts[1:3]
                        display_text = f"Title: {title} | Content: *****"

                    if display_text == selected_text:
                        selected_line = line
                        current_category = category
                        break

        if not selected_line:
            messagebox.showerror("Error", "Could not find the selected entry.")
            return

        parts = selected_line.split("|")
        if len(parts) < 2:
            messagebox.showerror("Error", "Selected entry is malformed.")
            return

        category = current_category

        # Create edit window
        edit_window = ctk.CTkToplevel(app)
        edit_window.title("Edit Entry")
        edit_window.geometry("400x350")

        if category == "Login":
            entry_type, email, enc_password = parts[1:]
            try:
                password = decrypt_data(enc_password, username)
            except:
                password = ""

            category_label = ctk.CTkLabel(edit_window, text="Category:")
            category_label.pack(pady=5)
            category_entry = ctk.CTkOptionMenu(edit_window, values=["Login"])
            category_entry.set(category)
            category_entry.pack(pady=5)

            type_label = ctk.CTkLabel(edit_window, text="Type:")
            type_label.pack(pady=5)
            type_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            type_entry.insert(0, entry_type)
            type_entry.pack(pady=5)

            email_label = ctk.CTkLabel(edit_window, text="Email:")
            email_label.pack(pady=5)
            email_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            email_entry.insert(0, email)
            email_entry.pack(pady=5)

            password_label = ctk.CTkLabel(edit_window, text="Password:")
            password_label.pack(pady=5)
            password_entry = ctk.CTkEntry(edit_window, show="*", fg_color="#f0f0f0")
            password_entry.insert(0, "*****")
            password_entry.pack(pady=5)

            def save_changes():
                new_type = type_entry.get().strip()
                new_email = email_entry.get().strip()
                new_password = password if password_entry.get() == "*****" else password_entry.get().strip()

                if not new_type or not new_email or not new_password:
                    messagebox.showwarning("Incomplete Data", "All fields are required.")
                    return

                encrypted_password = encrypt_data(new_password, username)
                new_line = f"Login|{new_type}|{new_email}|{encrypted_password}"

                # Update the file
                with open(files['CREDENTIALS_FILE'], "r") as f:
                    all_lines = f.readlines()

                for i, line in enumerate(all_lines):
                    if line.strip() == selected_line:
                        all_lines[i] = new_line + "\n"
                        break

                with open(files['CREDENTIALS_FILE'], "w") as f:
                    f.writelines(all_lines)

                load_credentials()
                edit_window.destroy()

        elif category == "Credit Card":
            card_name, card_number, card_expiry, enc_cvv = parts[1:5]
            try:
                cvv = decrypt_data(enc_cvv, username)
            except:
                cvv = ""

            category_label = ctk.CTkLabel(edit_window, text="Category:")
            category_label.pack(pady=5)
            category_entry = ctk.CTkOptionMenu(edit_window, values=["Credit Card"])
            category_entry.set(category)
            category_entry.pack(pady=5)

            name_label = ctk.CTkLabel(edit_window, text="Name on Card:")
            name_label.pack(pady=5)
            name_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            name_entry.insert(0, card_name)
            name_entry.pack(pady=5)

            number_label = ctk.CTkLabel(edit_window, text="Card Number:")
            number_label.pack(pady=5)
            number_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            number_entry.insert(0, card_number)
            number_entry.pack(pady=5)

            expiry_label = ctk.CTkLabel(edit_window, text="Expiry Date:")
            expiry_label.pack(pady=5)
            expiry_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            expiry_entry.insert(0, card_expiry)
            expiry_entry.pack(pady=5)

            cvv_label = ctk.CTkLabel(edit_window, text="CVV:")
            cvv_label.pack(pady=5)
            cvv_entry = ctk.CTkEntry(edit_window, show="*", fg_color="#f0f0f0")
            cvv_entry.insert(0, "*****")
            cvv_entry.pack(pady=5)

            def save_changes():
                new_name = name_entry.get().strip()
                new_number = number_entry.get().strip()
                new_expiry = expiry_entry.get().strip()
                new_cvv = cvv if cvv_entry.get() == "*****" else cvv_entry.get().strip()

                if not all([new_name, new_number, new_expiry, new_cvv]):
                    messagebox.showwarning("Incomplete Data", "All fields are required.")
                    return

                encrypted_cvv = encrypt_data(new_cvv, username)
                new_line = f"Credit Card|{new_name}|{new_number}|{new_expiry}|{encrypted_cvv}"

                with open(files['CREDENTIALS_FILE'], "r") as f:
                    all_lines = f.readlines()

                for i, line in enumerate(all_lines):
                    if line.strip() == selected_line:
                        all_lines[i] = new_line + "\n"
                        break

                with open(files['CREDENTIALS_FILE'], "w") as f:
                    f.writelines(all_lines)

                load_credentials()
                edit_window.destroy()

        elif category == "Notes":
            title, enc_content = parts[1:3]
            try:
                content = decrypt_data(enc_content, username)
            except:
                content = ""

            category_label = ctk.CTkLabel(edit_window, text="Category:")
            category_label.pack(pady=5)
            category_entry = ctk.CTkOptionMenu(edit_window, values=["Notes"])
            category_entry.set(category)
            category_entry.pack(pady=5)

            title_label = ctk.CTkLabel(edit_window, text="Title:")
            title_label.pack(pady=5)
            title_entry = ctk.CTkEntry(edit_window, fg_color="#f0f0f0")
            title_entry.insert(0, title)
            title_entry.pack(pady=5)

            content_label = ctk.CTkLabel(edit_window, text="Content:")
            content_label.pack(pady=5)
            content_entry = ctk.CTkTextbox(edit_window, width=300, height=150, fg_color="#f0f0f0")
            content_entry.insert("1.0", content)
            content_entry.pack(pady=5)

            def save_changes():
                new_title = title_entry.get().strip()
                new_content = content_entry.get("1.0", ctk.END).strip()

                if not all([new_title, new_content]):
                    messagebox.showwarning("Incomplete Data", "All fields are required.")
                    return

                encrypted_content = encrypt_data(new_content, username)
                new_line = f"Notes|{new_title}|{encrypted_content}"

                with open(files['CREDENTIALS_FILE'], "r") as f:
                    all_lines = f.readlines()

                for i, line in enumerate(all_lines):
                    if line.strip() == selected_line:
                        all_lines[i] = new_line + "\n"
                        break

                with open(files['CREDENTIALS_FILE'], "w") as f:
                    f.writelines(all_lines)

                load_credentials()
                edit_window.destroy()

        save_button = ctk.CTkButton(edit_window, text="Save Changes", command=save_changes)
        save_button.pack(pady=10)

    request_pin(after_pin)


def update_credentials_file():
    username = CURRENT_USER[0]
    files = get_user_files(username)
    entries = listbox.get(0, ctk.END)
    with open(files['CREDENTIALS_FILE'], "w") as f:
        for entry in entries:
            f.write(f"{entry}\n")

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
# Define show_login before using it in the button

def show_login():
    opening_frame.pack_forget()
    login_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Load the background image
opening_bg = ctk.CTkImage(
    light_image=Image.open("PasswordManager\Image Files\Welcome-Page.png"),
    size=(600, 750)
)

# Create and place the background label (must be added first to appear behind other widgets)
opening_bg_label = ctk.CTkLabel(opening_frame, image=opening_bg, text="")
opening_bg_label.place(relx=0.5, rely=0.5, anchor="center")  # Centered and fills the frame

# "Get Started!" button
get_started_btn = ctk.CTkButton(opening_frame, text="Get Started!", width=300, height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold"),
    command=lambda: on_button_click(), text_color="black", fg_color="white",
    border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50)
get_started_btn.place(relx=0.5, rely=0.8, anchor="center")


# Show the opening frame
opening_frame.pack(fill="both", expand=True, padx=20, pady=20)



# ---------- LOGIN PAGE ---------- #
for widget in login_frame.winfo_children():
    widget.destroy()

# Load the background image
login_bg = ctk.CTkImage(
    light_image=Image.open("PasswordManager\Image Files\LogIn-Page.png"),
    size=(600, 750)
)

login_bg_label = ctk.CTkLabel(login_frame, image=login_bg, text="")
login_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

# Username and password entries
login_user_entry = ctk.CTkEntry(
    login_frame,
    placeholder_text="Username",
    placeholder_text_color="#D9D9D9",
    fg_color="#FEFEFE",
    text_color="black",
    border_color="#D9D9D9",
    border_width=1,
    corner_radius=8,
    width=300,
    height=50,
    font=ctk.CTkFont(size=18)
)
login_user_entry.place(relx=0.5, rely=0.43, anchor="center")

login_pass_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
login_pass_frame.place(relx=0.52, rely=0.55, anchor="center")  # adjust as needed
login_pass_entry = ctk.CTkEntry(
    login_pass_frame,
    placeholder_text="Password",
    show="*",
    placeholder_text_color="#D9D9D9",
    fg_color="#FEFEFE",
    text_color="black",
    border_color="#D9D9D9",
    border_width=1,
    corner_radius=8,
    width=255,
    height=40,
    font=ctk.CTkFont(size=18)
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
login_eye_btn.pack(side="left", padx=0)

login_eye_btn.bind("<Enter>", lambda e: login_eye_btn.configure(text_color="#5F5F5F") if not login_pw_visible[0] else None)
login_eye_btn.bind("<Leave>", lambda e: login_eye_btn.configure(text_color="#D9D9D9") if not login_pw_visible[0] else None)

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





# ---------- REGISTER PAGE ---------- #
for widget in register_frame.winfo_children():
    widget.destroy()

# Load the background image
register_bg = ctk.CTkImage(
    light_image=Image.open("PasswordManager\Image Files\Register Page (1).png"),
    size=(600, 750)
)
register_bg_label = ctk.CTkLabel(register_frame, image=register_bg, text="")
register_bg_label.place(relx=0.5, rely=0.5, anchor="center")  

# Create a form_frame to hold all registration widgets
form_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
form_frame.place(relx=0.5, rely=0.275, anchor="n")  # Adjust rely as needed for vertical centering

# Username (Registration)
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

# Password (Registration)
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

# Load the generate password icon as a CTkImage
generate_pass_img = ctk.CTkImage(light_image=Image.open("PasswordManager\Image Files\Generate-Pass-Icon.png"), size=(32, 32))

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


# Inner frame containing all requirement labels (pack/unpack happens here)
req_frame = ctk.CTkFrame(form_frame, fg_color="transparent")
req_frame.pack(anchor="w", pady=(0, 8))

# Your existing labels inside req_frame
length_req = ctk.CTkLabel(req_frame, text="• 6-20 characters", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
length_req.pack(anchor="w", pady=1)

name_req = ctk.CTkLabel(req_frame, text="• DO NOT contain username", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
name_req.pack(anchor="w", pady=1)

upper_req = ctk.CTkLabel(req_frame, text="• One uppercase letter", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
upper_req.pack(anchor="w", pady=1)

number_req = ctk.CTkLabel(req_frame, text="• One number", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
number_req.pack(anchor="w", pady=1)

special_req = ctk.CTkLabel(req_frame, text="• One special character", text_color="gray", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=12))
special_req.pack(anchor="w", pady=1)

# Your existing update_password_requirements function remains unchanged
def update_password_requirements(event=None):
    password = reg_pass_entry.get()
    unmet = 0
    # Update length requirement
    if 6 <= len(password) <= 20:
        length_req.pack_forget()
    else:
        length_req.pack(anchor="w", pady=1)
        unmet += 1
    # Update uppercase requirement
    if any(c.isupper() for c in password):
        upper_req.pack_forget()
    else:
        upper_req.pack(anchor="w", pady=1)
        unmet += 1
    # Update number requirement
    if any(c.isdigit() for c in password):
        number_req.pack_forget()
    else:
        number_req.pack(anchor="w", pady=1)
        unmet += 1
    # Update special character requirement
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        special_req.pack_forget()
    else:
        special_req.pack(anchor="w", pady=1)
        unmet += 1
    # Always keep the requirements frame packed
    if not req_frame.winfo_ismapped():
        req_frame.pack(anchor="w", pady=(0, 8))
    # Move Confirm Password field up as requirements are fulfilled
    total_reqs = 4
    min_rely = 0.90  # Closest to password (just below password)
    max_rely = 0.67  # Farthest (final/original position)
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

# Create a button frame at the bottom of the register_frame
button_frame = ctk.CTkFrame(register_frame, fg_color="transparent")
button_frame.place(relx=0.5, rely=1.0, anchor="s", relwidth=0.7, y=-35)  # y=-60 moves it higher

# Sign up button
reg_button = ctk.CTkButton(
    button_frame,
    text="SIGN UP",
    width=300,
    height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20),
    command=register_user,
    text_color="black",
    fg_color="transparent",         # Light pink/white
    border_color="black",
    border_width=2,
    hover_color="#FFF6FA",      # Slightly lighter on hover
    corner_radius=50
)
reg_button.pack(pady=(0, 10))

# Back to login button
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
# Background image
main_bg = ctk.CTkImage(
    light_image=Image.open("PasswordManager\Image Files\Main-Page.png"),
    size=(600, 750)
)
main_bg_label = ctk.CTkLabel(main_frame, image=main_bg, text="")
main_bg_label.place(relx=0.5, rely=0.5, anchor="center")  


# Outer frame as black border with rounded corners
border_frame = ctk.CTkFrame(main_frame, fg_color="black", corner_radius=50)
border_frame.place(relx=0.27, rely=0.26, anchor="center")

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
    fg_color="#ff94c2",        # lighter pink
    hover_color="#ff6fa1",     # darker pink when hovered
    text_color="#222",
    font=ctk.CTkFont("Arial", size=20, weight="bold"),
    corner_radius=20,
    border_color="black",     # black border
    border_width=5,           # thickness of the border
    command=show_add_password
)
add_pass_btn.place(relx=0.75, rely=0.26, anchor="center")  # anchor for better centering

# ---------- CREDENTIAL CONTAINER ----------
credentials_container = ctk.CTkFrame(main_frame, fg_color="#ffffff")
credentials_container.place(relx=0.5, rely=0.62, anchor="center", relwidth=0.9, relheight=0.6)

# Load icons
asterisk_icon = ctk.CTkImage(light_image=Image.open("PasswordManager\Image Files\icon1.png"), size=(40, 40))
card_icon = ctk.CTkImage(light_image=Image.open("PasswordManager\Image Files\icon2.png"), size=(45, 40))
note_icon = ctk.CTkImage(light_image=Image.open("PasswordManager\Image Files\icon3.png"), size=(40, 40))

# Update credential cards

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
        # Card style: white, rounded, border
        card = ctk.CTkFrame(credentials_container, fg_color="white", corner_radius=14, border_width=2, border_color="#bbb")
        card.pack(fill="x", pady=8, padx=2)
        card.pack_propagate(False)
        card.configure(height=70)
        # Info text and icon
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
        # Layout: left info, right icon
        left = ctk.CTkFrame(card, fg_color="transparent")
        left.pack(side="left", fill="both", expand=True, padx=16, pady=8)
        title_label = ctk.CTkLabel(left, text=title, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=16, weight="bold"), text_color="#111")
        title_label.pack(anchor="w")
        subtitle_label = ctk.CTkLabel(left, text=subtitle, font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=13), text_color="#444")
        subtitle_label.pack(anchor="w")
        icon_label = ctk.CTkLabel(card, image=icon, text="", fg_color="transparent")
        icon_label.pack(side="right", padx=18)
        # Make the whole card clickable
        card.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        left.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        title_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        subtitle_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))
        icon_label.bind('<Button-1>', lambda e, idx=idx, parts=parts, category=category, lines=lines: show_credential_details(idx, parts, category, lines))

# Update vault filter to refresh on change
vault_filter.configure(command=lambda x: refresh_main_credentials())

# ---------- LOGOUT BUTTON ----------
logout_btn_frame = ctk.CTkFrame(main_frame, fg_color="#FFFFFF")
logout_btn_frame.place(relx=1, rely=1, anchor="se", x=-10, y=-10)

logout_btn = ctk.CTkButton(
    logout_btn_frame,
    text="➡️", width=60, height=60,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"),
    command=logout, text_color="black", fg_color="transparent", border_color="black", border_width=2, hover_color="#FEF5F5", corner_radius=50
)
logout_btn.place(relx=0.5, rely=0.5, anchor="center") 


# Call this after login or when returning to main page
def show_main():
    login_frame.pack_forget()
    register_frame.pack_forget()
    add_frame.pack_forget()
    view_frame.pack_forget()
    edit_frame.pack_forget()
    main_frame.pack(fill="both", expand=True, padx=0, pady=0)
    refresh_main_credentials()






# ---------- ADD PASSWORD PAGE ---------- #
# Background image
add_bg = ctk.CTkImage(
    light_image=Image.open("PasswordManager\Image Files\Add-Paswrod.png"),
    size=(600, 750)
)
add_bg_label = ctk.CTkLabel(add_frame, image=add_bg, text="", fg_color="#FFFFFF")
add_bg_label.place(relx=0.5, rely=0.5, anchor="center")


fields_frame = ctk.CTkFrame(add_frame, fg_color="#FFFFFF", width=400, height=400)
fields_frame.place(relx=0.5, rely=0.5, anchor="center")


# Login fields
login_fields = ctk.CTkFrame(fields_frame, fg_color="#FFFFFF")
type_entry = ctk.CTkEntry(login_fields, placeholder_text="Type", fg_color="#f0f0f0", width=300, height=50, text_color="black", font=ctk.CTkFont(size=20))
type_entry.pack(pady=(10,5), fill="x", padx=20)

email_entry = ctk.CTkEntry(login_fields, placeholder_text="Email/Username", fg_color="#f0f0f0", width=300, height=50, text_color="black", font=ctk.CTkFont(size=20))
email_entry.pack(pady=5, fill="x", padx=20)

password_entry = ctk.CTkEntry(login_fields, placeholder_text="Password", show="*", fg_color="#f0f0f0", width=300, height=50, text_color="black", font=ctk.CTkFont(size=20))
password_entry.pack(pady=5, fill="x", padx=20)


# Credit Card fields
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


# Notes fields
notes_fields = ctk.CTkFrame(fields_frame, fg_color="#FFFFFF")
notes_title_entry = ctk.CTkEntry(notes_fields, placeholder_text="Title", fg_color="#f0f0f0", width=300, height=45, text_color="black", font=ctk.CTkFont(size=20))
notes_title_entry.pack(pady=(10, 5), fill="x", padx=20)

notes_content = ctk.CTkTextbox(notes_fields, width=400, height=180, text_color="black", fg_color="#f0f0f0")
notes_content.pack(pady=(5, 15), padx=20)


# Switch category logic
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

# Outer frame as black border with rounded corners
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


save_btn = ctk.CTkButton(
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
save_btn.place(relx=0.25, rely=0.92, anchor="center")

back_btn = ctk.CTkButton(
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
back_btn.place(relx=0.73, rely=0.92, anchor="center")

# ---------- VIEW PASSWORD PAGE ---------- #
# Background image // 
detail_bg = ctk.CTkImage(
    light_image=Image.open("PasswordManager\Image Files\View-Vault.png"),
    size=(600, 750)
)
detail_bg_label = ctk.CTkLabel(details_frame, image=detail_bg, text="", fg_color="#FFFFFF")
detail_bg_label.place(relx=0.5, rely=0.5, anchor="center")

# Show passwords toggle variable
show_pw_var = ctk.BooleanVar(value=False)


# Textbox for credential details
details_text = ctk.CTkTextbox(
    details_frame,
    width=480,
    height=220,
    font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=14),
    fg_color="#222",
    text_color="white"
)
details_text.place(relx=0.5, rely=0.5, anchor="center")
details_text.configure(state="disabled")

# Password toggle switch with styling and PIN callback
pw_toggle = ctk.CTkSwitch(
    details_frame,
    text="Show Passwords",
    variable=show_pw_var, border_color="black", border_width=2,
    font=ctk.CTkFont(size=18, weight="bold")
)
pw_toggle.place(relx=0.5, rely=0.7, anchor="center")

# Buttons frame
custom_font = ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=20, weight="bold")

# Button frame (for Edit & Delete)
btn_frame = ctk.CTkFrame(details_frame, fg_color="transparent")
btn_frame.place(relx=0.56, rely=0.8, anchor="center")


edit_btn = ctk.CTkButton(
    btn_frame, text="🖉  Edit", width=140, height=60,
    font=custom_font, text_color="black", fg_color="transparent",
    border_color="black", border_width=2, hover_color="#FEF5F5",
    corner_radius=50
)
edit_btn.pack(side="left", padx=8)

delete_btn = ctk.CTkButton(
    btn_frame, text="🗑️  Delete", width=140, height=60,
    font=custom_font, text_color="black", fg_color="transparent",
    border_color="#d32f2f", border_width=2, hover_color="#FFE5E5",
    corner_radius=50
)
delete_btn.pack(side="left", padx=8)

# Back button
back_btn = ctk.CTkButton(
    details_frame, text="<", width=50, height=60,
    font=custom_font, text_color="black", fg_color="transparent",
    border_color="black", border_width=2, hover_color="#FEF5F5",
    corner_radius=50, command=main_frame
)
back_btn.place(relx=0.2, rely=0.8, anchor="center")







# Credential state
current_cred = {'parts': None, 'category': None, 'idx': None, 'lines': None}

def update_details_text():
    details_text.configure(state="normal")
    details_text.delete("1.0", ctk.END)
    parts = current_cred['parts']
    category = current_cred['category']
    username = CURRENT_USER[0]
    show_pw = show_pw_var.get()

    if not parts or not category:
        details_text.insert("1.0", "No credential selected.")
        details_text.configure(state="disabled")
        return

    try:
        if category == "Login":
            entry_type, email, enc_password = parts[1:]
            password = decrypt_data(enc_password, username) if show_pw else "*****"
            details = f"Category: Login\nType: {entry_type}\nEmail: {email}\nPassword: {password}"

        elif category == "Credit Card":
            card_name, card_number, card_expiry, enc_cvv = parts[1:]
            cvv = decrypt_data(enc_cvv, username) if show_pw else "*****"
            details = f"Category: Credit Card\nName: {card_name}\nNumber: {card_number}\nExpiry: {card_expiry}\nCVV: {cvv}"

        elif category == "Notes":
            title, enc_content = parts[1:]
            content = decrypt_data(enc_content, username) if show_pw else "*****"
            details = f"Category: Notes\nTitle: {title}\nContent: {content}"

        else:
            details = "Unknown credential format"

    except Exception as e:
        details = f"[Error decrypting data: {str(e)}]"

    details_text.insert("1.0", details)
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

# Initialize display
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




# ---------- EDIT PASSWORD PAGE ---------- #
edit_label = ctk.CTkLabel(edit_frame, text="✏️ Edit Credentials", font=ctk.CTkFont(family="BricolageGrotesque-VariableFont_opsz,wdth,wght.ttf", size=24, weight="bold"))
edit_label.pack(pady=10)

# Add category filter
edit_category_filter_label = ctk.CTkLabel(edit_frame, text="Filter by Category:")
edit_category_filter_label.pack(pady=5)
edit_category_filter = ctk.CTkOptionMenu(
    edit_frame,
    values=["All", "Login", "Credit Card", "Notes"],
    command=lambda x: load_credentials(),
    width=260,
    height=35,
    fg_color="white",
    button_color="white",
    button_hover_color="#f0f0f0",
    text_color="black",
    dropdown_fg_color="white",
    dropdown_hover_color="#f0f0f0",
    dropdown_text_color="black"
)
edit_category_filter.set("All")
edit_category_filter.pack(pady=5)

listbox_frame = ctk.CTkFrame(edit_frame)
listbox_frame.pack(pady=10, fill="both", expand=True)

scrollbar = Scrollbar(listbox_frame)
scrollbar.pack(side="right", fill="y")

listbox = Listbox(listbox_frame, yscrollcommand=scrollbar.set, width=60, height=15, font=("Courier", 12))
listbox.pack(side="left", fill="both", expand=True)

scrollbar.config(command=listbox.yview)

edit_button = ctk.CTkButton(edit_frame, text="Edit Selected", command=edit_selected, text_color="white")
edit_button.pack(pady=5)

delete_button = ctk.CTkButton(edit_frame, text="Delete Selected", command=delete_selected, text_color="white")
delete_button.pack(pady=5)

back_edit_btn = ctk.CTkButton(edit_frame, text="Back", command=show_main, text_color="white")
back_edit_btn.pack(pady=5)

# Edit and delete button logic
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
    back_btn.configure(command=back_action)

    main_frame.pack_forget()
    details_frame.pack(fill="both", expand=True)


# --- Move edit_credential_in_page and update_credential_line above show_credential_details --- #
def update_credential_line(old_line, new_line):
    username = CURRENT_USER[0]
    files = get_user_files(username)
    with open(files['CREDENTIALS_FILE'], 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    with open(files['CREDENTIALS_FILE'], 'w') as f:
        for line in lines:
            if line == old_line:
                f.write(new_line + "\n")
            else:
                f.write(line + "\n")


def edit_credential_in_page(parts, original_line):
    # Before allowing edits, request PIN to verify user
    def on_pin_verified(success):
        if not success:
            messagebox.showerror("Error", "PIN verification failed. Cannot edit credential.")
            return  # Do not proceed to edit page

        # PIN verified - proceed with opening edit page
        username = CURRENT_USER[0]
        files = get_user_files(username)
        category = parts[0]
        selected_line = original_line

        # Switch frames
        main_frame.pack_forget()
        view_frame.pack_forget()
        add_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Set category and show relevant fields
        category_entry.set(category)
        switch_category_fields(category)

        # Pre-fill fields with decrypted data
        if category == "Login":
            entry_type, email, enc_password = parts[1:4]
            # Keep password masked by default, do NOT decrypt password here
            password = "*****"
            type_entry.delete(0, ctk.END)
            type_entry.insert(0, entry_type)
            email_entry.delete(0, ctk.END)
            email_entry.insert(0, email)
            password_entry.delete(0, ctk.END)
            password_entry.insert(0, password)

        elif category == "Credit Card":
            name, number, expiry, enc_cvv = parts[1:5]
            # Mask CVV by default
            cvv = "*****"
            card_name_entry.delete(0, ctk.END)
            card_name_entry.insert(0, name)
            card_number_entry.delete(0, ctk.END)
            card_number_entry.insert(0, number)
            card_expiry_entry.delete(0, ctk.END)
            card_expiry_entry.insert(0, expiry)
            card_cvv_entry.delete(0, ctk.END)
            card_cvv_entry.insert(0, cvv)

            # Update card type label
            global card_number_label, card_error_label
            if card_number_label is not None:
                card_number_label.destroy()
            if card_error_label is not None:
                card_error_label.destroy()
                
            card_number_label = ctk.CTkLabel(add_frame, text="")
            card_number_label.pack(pady=5)
            card_error_label = ctk.CTkLabel(add_frame, text="", text_color="red")
            card_error_label.pack(pady=2)

            if number.startswith("4"):
                card_number_label.configure(text="Visa")
            elif number.startswith("5") or number.startswith("2"):
                card_number_label.configure(text="Mastercard")
            else:
                card_number_label.configure(text="Unknown")

        elif category == "Notes":
            title, enc_content = parts[1:3]
            # Mask notes content (optional, but consistent)
            content = "*****"
            notes_title_entry.delete(0, ctk.END)
            notes_title_entry.insert(0, title)
            notes_content.delete("1.0", ctk.END)
            notes_content.insert("1.0", content)

        # Update function
        def update_changes():
            if category == "Login":
                new_type = type_entry.get().strip()
                new_email = email_entry.get().strip()
                new_password = password_entry.get().strip()
                if not all([new_type, new_email, new_password]):
                    messagebox.showwarning("Incomplete", "All fields are required.")
                    return
                # Encrypt password before saving
                encrypted = encrypt_data(new_password, username)
                new_line = f"Login|{new_type}|{new_email}|{encrypted}"

            elif category == "Credit Card":
                new_name = card_name_entry.get().strip()
                new_number = card_number_entry.get().strip()
                new_expiry = card_expiry_entry.get().strip()
                new_cvv = card_cvv_entry.get().strip()

                if card_error_label is not None:
                    card_error_label.configure(text="")
                if card_number_label is not None:
                    card_number_label.configure(text="")

                if not all([new_name, new_number, new_expiry, new_cvv]):
                    if card_error_label is not None:
                        card_error_label.configure(text="Please fill in all card fields.")
                    return

                import re
                if not re.match(r"^\d{4}-\d{4}-\d{4}-\d{4}$", new_number):
                    if card_error_label is not None:
                        card_error_label.configure(text="Invalid Card Details")
                    return

                if not (new_number.startswith("4") or new_number.startswith("5") or new_number.startswith("2")):
                    if card_error_label is not None:
                        card_error_label.configure(text="Invalid Card Details")
                    return

                if not re.match(r"^(0[1-9]|1[0-2])/\d{2}$", new_expiry):
                    if card_error_label is not None:
                        card_error_label.configure(text="Invalid Card Details")
                    return

                if not re.match(r"^\d{3}$", new_cvv):
                    if card_error_label is not None:
                        card_error_label.configure(text="Invalid Card Details")
                    return

                if new_number.startswith("4"):
                    if card_number_label is not None:
                        card_number_label.configure(text="Visa")
                elif new_number.startswith("5") or new_number.startswith("2"):
                    if card_number_label is not None:
                        card_number_label.configure(text="Mastercard")
                else:
                    if card_number_label is not None:
                        card_number_label.configure(text="Unknown")

                encrypted = encrypt_data(new_cvv, username)
                new_line = f"Credit Card|{new_name}|{new_number}|{new_expiry}|{encrypted}"

            elif category == "Notes":
                new_title = notes_title_entry.get().strip()
                new_content = notes_content.get("1.0", ctk.END).strip()
                if not all([new_title, new_content]):
                    messagebox.showwarning("Incomplete", "All fields are required.")
                    return
                encrypted = encrypt_data(new_content, username)
                new_line = f"Notes|{new_title}|{encrypted}"

            # Update the credential file with new line
            update_credential_line(selected_line, new_line)

            # Show success and return to main
            messagebox.showinfo("Success", "Credential updated.")
            show_main()

        # Update button commands
        save_btn.configure(text="Update", command=update_changes)
        back_btn.configure(text="Cancel", command=show_main)

    # Start PIN verification before edit
    request_pin(on_pin_verified)


app.mainloop()
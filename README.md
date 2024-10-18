# Blowfish Encryption Web Application

Welcome to the **Blowfish Encryption Web Application**! This project demonstrates the implementation of the Blowfish algorithm using **HTML** for the frontend and **Python Flask** for the backend. With an intuitive interface, you can encrypt and decrypt text securely right from your browser.

## 💻 Quick Start

Follow these steps to get the application up and running:

### 1.Clone the repository
```bash
git clone https://github.com/Sarvani-5/BlowfishAlgorithm.git
```

### 2. Install Dependencies
Before running the app, make sure to install Flask. Simply open your terminal or command prompt and run:

```bash
pip install flask
```

### 3. Navigate to Project Directory
Move into the project folder where the application files are located:

```bash
cd [project location]
```
Replace `[project location]` with the actual path to your project directory.

### 4. Launch the Application
Now, start the Flask server by running:
```bash
python app.py
```
### 5. Access the Application
Once the server is up, you'll see a local URL provided in your terminal (usually something like `http://127.0.0.1:5000`). Open your web browser, paste this link, and hit Enter to access the Blowfish Encryption Web Application.

## 🌟 Features
- **Simple and Secure**: Easily encrypt and decrypt messages using the robust Blowfish algorithm.
- **Interactive UI**: Intuitive, user-friendly web interface developed using HTML.
- **Flask Backend**: Flask provides a seamless and lightweight server to handle encryption requests.

## 🎯 How It Works
- **Encryption**: Enter the text or upload a text file along with a key, click 'Encrypt', and your input will be transformed into a secure ciphertext using the Blowfish algorithm.
- **Decryption**:  Provide the encrypted text or upload an encrypted file along with the key, hit 'Decrypt', and the original message will be restored.
  
## 📂 Project Structure
- `app.py`: Flask application that powers the backend.
- `blowfish.py`:Contains the logic for the implementation of blowfish algorithm.
- `templates/`: Contains HTML files for the web interface.





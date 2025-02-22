**Secure Data Hiding in Images Using Steganography**

**Features**
Secure Message Hiding: Embed encrypted messages into images using steganography.
Encryption & Decryption: Supports text encryption before hiding and decryption upon retrieval.
Digital Signature Verification: Ensures message integrity with digital signatures.
Web-Based Interface: User-friendly web application built with Flask.
PNG Image Support: Allows only PNG files for better quality and reliability.
Error Handling: Provides feedback messages for invalid file uploads or failed verifications.

**How It Works**
Encryption & Hiding:
User uploads a PNG image and enters the message.
The message is encrypted using a selected encryption method.
A digital signature is generated for integrity verification.
The encrypted message and signature are embedded into the image.
The processed image is available for download.
Decryption & Extraction:
User uploads a steganographic image.
The hidden message is extracted.
Signature verification ensures authenticity.
If verified, the message is decrypted and displayed.

**Installation**
Clone the repository:
git clone https://github.com/your-repo/steganography-digital-signature.git
cd steganography-digital-signature
Create a virtual environment (optional but recommended):
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
Install dependencies:
pip install flask pillow cryptography werkzeug
Run the application:
python app.py
Access the application:
Open a browser and go to http://127.0.0.1:5000/.

**Usage**
Encrypt & Hide a Message:
Navigate to the Encrypt page.
Upload a PNG image and enter a secret message.
Choose an encryption method and submit.
Download the processed image containing the hidden message.
Extract & Decrypt a Message:
Navigate to the Decrypt page.
Upload a steganographic image.
View the extracted message after signature verification.

**Technologies Used**
Python - Core programming language
Flask - Web framework
Pillow - Image processing
Cryptography - Encryption & digital signature handling
Werkzeug - Secure file handling
HTML, CSS, JavaScript - Frontend technologies

**Future Enhancements**
Support for Multiple Image Formats (JPG, BMP, etc.)

Advanced Encryption Options (AES, RSA, etc.)

Improved UI/UX with better animations

Cloud Storage Integration for secure message storage

Mobile Compatibility for easy access

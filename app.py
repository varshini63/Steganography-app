# app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
from utils.steganography import hide_text, extract_text
from utils.encryption import encrypt_text, decrypt_text, generate_signature, verify_signature

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

ALLOWED_EXTENSIONS = {'png'}  # Changed to PNG only

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            text = request.form.get('text')
            encryption_method = request.form.get('encryption')

            try:
                # Encrypt the text
                encrypted_text = encrypt_text(text, encryption_method)
                print(f"Encrypted Text: {encrypted_text}")

                # Generate digital signature
                signature = generate_signature(encrypted_text)
                print(f"Signature: {signature}")

                # Combine encryption method, encrypted text, and signature
                combined_text = f"{encryption_method}::{encrypted_text}::{signature}"
                print(f"Combined Text: {combined_text}")

                # Hide the combined text in the image
                output_filename = f"stego_{filename}"
                output_filepath = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
                hide_text(filepath, output_filepath, combined_text)

                flash('Image processed successfully!')
                return render_template('encrypt.html', output_image=output_filename)
            except Exception as e:
                flash(f'Error during encryption: {str(e)}')
                return redirect(request.url)
        else:
            flash('Allowed image type is PNG.')
            return redirect(request.url)
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            # Extract the combined text
            combined_text = extract_text(filepath)
            if not combined_text:
                flash('No hidden text found.')
                return redirect(request.url)

            try:
                encryption_method, encrypted_text, signature = combined_text.split("::")
                print(f"Encryption Method: {encryption_method}")
                print(f"Encrypted Text: {encrypted_text}")
                print(f"Signature: {signature}")

                # Verify the signature
                if verify_signature(encrypted_text, signature):
                    # Decrypt the text
                    decrypted_text = decrypt_text(encrypted_text, encryption_method)
                    print(f"Decrypted Text: {decrypted_text}")
                    flash('Text extracted and verified successfully!')
                    return render_template('decrypt.html', extracted_text=decrypted_text)
                else:
                    flash('Signature verification failed!')
                    return redirect(request.url)
            except ValueError:
                flash('Incorrect data format.')
                return redirect(request.url)
            except Exception as e:
                flash(f'Error during decryption: {str(e)}')
                return redirect(request.url)
        else:
            flash('Allowed image type is PNG.')
            return redirect(request.url)
    return render_template('decrypt.html')

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)

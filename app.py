from flask import Flask, request, jsonify, render_template
import pyotp
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

# Mock database for demonstration purposes
users_db = {
    "user1": {"password_hash": hashlib.sha256("user_password".encode()).hexdigest(), "otp_secret": pyotp.random_base32()}
}

# Key generation and serialization
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open('private_key.pem', 'wb') as f:
        f.write(private_pem)
        
    with open('public_key.pem', 'wb') as f:
        f.write(public_pem)
        
generate_rsa_key_pair()

def load_rsa_keys():
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    
    return private_key, public_key

def encrypt_message(message, public_key):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(encrypted_message, private_key):
    decrypted = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

private_key, public_key = load_rsa_keys()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data['message']
    encrypted_message = encrypt_message(message, public_key)
    return jsonify({"encrypted_message": encrypted_message.decode('latin1')})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted_message = data['encrypted_message'].encode('latin1')
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return jsonify({"decrypted_message": decrypted_message})

@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = users_db.get(username)
    if user and user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
        otp = data['otp']
        if pyotp.TOTP(user['otp_secret']).verify(otp):
            return jsonify({"status": "success"})
        else:
            return jsonify({"status": "failure", "message": "Invalid OTP"})
    else:
        return jsonify({"status": "failure", "message": "Invalid username or password"})

if __name__ == '__main__':
    app.run(debug=True)

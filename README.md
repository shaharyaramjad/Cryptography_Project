# 🔐 Secure File Encryption & Digital Signature System

This project implements **secure file encryption and decryption** using **AES-256** encryption, 
**RSA-2048** key exchange, and **ECDSA digital signatures** to ensure **confidentiality, integrity, authenticity, and non-repudiation** of sensitive data.

---

## 📌 **Features**
✅ **File Encryption & Decryption** using AES-256 in CFB Mode  
✅ **Key Exchange** using RSA-2048 (Public-Private Key Pair)  
✅ **Digital Signature Verification** using ECDSA (Elliptic Curve Digital Signature Algorithm)  
✅ **Data Integrity Check** with SHA-256 Hashing  
✅ **Authentication** using X.509 Digital Certificates  

---

## 🔑 **Cryptographic Techniques Used**
### **1️⃣ Encryption: AES-256 (Cipher Feedback Mode)**
- Symmetric encryption algorithm for **fast and secure file encryption**.
- **CFB Mode** used to ensure **stream-like encryption** without requiring padding.
- Key Length: **256-bit** (Resistant to brute-force attacks).

### **2️⃣ Key Exchange: RSA-2048**
- Ensures **secure transmission of AES keys** over an insecure channel.
- Only the intended recipient (Bob) can decrypt the AES key using **his private RSA key**.
- RSA Key Length: **2048-bit** (Current cryptographic standard).

### **3️⃣ Digital Signatures: ECDSA-256**
- Ensures **authenticity & integrity** by signing the encrypted file.
- Signature verification prevents unauthorized modifications.
- Uses **Elliptic Curve Cryptography (ECC)**, making it more efficient than RSA.

### **4️⃣ Hashing: SHA-256**
- Used for **data integrity checks** in ECDSA signing.
- Ensures **collision resistance**, preventing tampering with the original data.

---

## 🚀 **How to Run This Project**
### **🔹 Prerequisites**
1. Install **Python 3.x**
2. Install required cryptography libraries:
   ```sh
   pip install cryptography pycryptodome

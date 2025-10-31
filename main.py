import os
import shutil
import subprocess
import sys
from pathlib import Path

# ---------- კონფიგი ----------
REPO_DIR = Path(__file__).resolve().parent
MESSAGE_TXT = REPO_DIR / "message.txt"

PRIVATE_PEM = REPO_DIR / "private.pem"
PUBLIC_PEM  = REPO_DIR / "public.pem"

RSA_ENC = REPO_DIR / "message_rsa_encrypted.bin"
RSA_DEC = REPO_DIR / "message_rsa_decrypted.txt"

AES_KEY = REPO_DIR / "aes_key.bin"   # 32 bytes (256-bit)
AES_IV  = REPO_DIR / "aes_iv.bin"    # 16 bytes (128-bit)
AES_ENC = REPO_DIR / "message_aes_encrypted.bin"
AES_DEC = REPO_DIR / "message_aes_decrypted.txt"

RSA_VS_AES = REPO_DIR / "rsa_vs_aes.txt"


# ---------- OpenSSL პოვნა ----------
def find_openssl() -> str:
    exe = shutil.which("openssl")
    if exe:
        return exe
    # Windows ჩვეულებრივი გზა
    win_default = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    if os.path.exists(win_default):
        return win_default
    print("Error: OpenSSL Not Found")
    sys.exit(1)

OPENSSL = find_openssl()

def run(cmd: list[str]):
    """გაუშვი openssl ბრძანება მკაფიო შეცდომებით."""
    print(">>", " ".join(cmd))
    subprocess.run(cmd, check=True)


# ---------- ნაბიჯი 1: message.txt ----------
def ensure_message():
    if not MESSAGE_TXT.exists():
        MESSAGE_TXT.write_text(
            "This is a secret message that must be encrypted and decrypted using OpenSSL.\n",
            encoding="utf-8"
        )
        print("OK: message.txt Success.")
    else:
        print("OK: message.txt Already Exists.")


# ---------- ნაბიჯი 2: RSA გასაღებები (OpenSSL 3+: genpkey/pkey) ----------
def ensure_rsa_keys():
    if not PRIVATE_PEM.exists():
        run([OPENSSL, "genpkey", "-algorithm", "RSA",
             "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", str(PRIVATE_PEM)])
        print("OK: private.pem Generated.")
    else:
        print("OK: private.pem Already Exists.")

    if not PUBLIC_PEM.exists():
        run([OPENSSL, "pkey", "-in", str(PRIVATE_PEM),
             "-pubout", "-out", str(PUBLIC_PEM)])
        print("OK: public.pem Generated.")
    else:
        print("OK: public.pem Already Exists.")


# ---------- ნაბიჯი 3: RSA დაშიფვრა/გაშიფვრა (pkeyutl, OAEP-SHA256) ----------
def rsa_encrypt_decrypt():
    # Encryption (public.pem)
    run([OPENSSL, "pkeyutl",
         "-encrypt",
         "-pubin", "-inkey", str(PUBLIC_PEM),
         "-in", str(MESSAGE_TXT),
         "-out", str(RSA_ENC),
         "-pkeyopt", "rsa_padding_mode:oaep",
         "-pkeyopt", "rsa_oaep_md:sha256"])
    print(f"OK: RSA encryption → {RSA_ENC.name}")

    # Decryption (private.pem)
    run([OPENSSL, "pkeyutl",
         "-decrypt",
         "-inkey", str(PRIVATE_PEM),
         "-in", str(RSA_ENC),
         "-out", str(RSA_DEC),
         "-pkeyopt", "rsa_padding_mode:oaep",
         "-pkeyopt", "rsa_oaep_md:sha256"])
    print(f"OK: RSA decryption → {RSA_DEC.name}")


# ---------- ნაბიჯი 4: AES-256-CBC სიმეტრიული დაშიფვრა ----------
def ensure_aes_key_iv():
    if not AES_KEY.exists():
        run([OPENSSL, "rand", "-out", str(AES_KEY), "32"])  # 256-bit key
        print("OK: aes_key.bin Generated.")
    else:
        print("OK: aes_key.bin Already Exists.")

    if not AES_IV.exists():
        run([OPENSSL, "rand", "-out", str(AES_IV), "16"])   # 128-bit IV
        print("OK: aes_iv.bin Generated.")
    else:
        print("OK: aes_iv.bin Already Exists.")

def aes_encrypt_decrypt():
    key_hex = AES_KEY.read_bytes().hex()
    iv_hex  = AES_IV.read_bytes().hex()

    # Encryption
    run([OPENSSL, "enc", "-aes-256-cbc",
         "-in", str(MESSAGE_TXT),
         "-out", str(AES_ENC),
         "-K", key_hex, "-iv", iv_hex])
    print(f"OK: AES encryption → {AES_ENC.name}")

    # Decryption
    run([OPENSSL, "enc", "-d", "-aes-256-cbc",
         "-in", str(AES_ENC),
         "-out", str(AES_DEC),
         "-K", key_hex, "-iv", iv_hex])
    print(f"OK: AES decryption → {AES_DEC.name}")


# ---------- ნაბიჯი 5: მოკლე ახსნა (rsa_vs_aes.txt) ----------
def write_rsa_vs_aes():
    if not RSA_VS_AES.exists():
        RSA_VS_AES.write_text(
            "RSA (asymmetric encryption) uses a pair of keys: a public key for encryption and a private key for decryption.\n"
            "It is computationally slower but provides secure key exchange and digital signatures.\n"
            "It is best used for protecting small amounts of data, such as encrypting symmetric keys.\n\n"
            "AES-256 (symmetric encryption) uses a single shared key for both encryption and decryption.\n"
            "It is extremely fast and efficient for encrypting large files or continuous data streams.\n\n"
            "Performance difference:\n"
            "AES is much faster than RSA because it performs simpler mathematical operations.\n"
            "RSA involves modular exponentiation and large integer arithmetic, which is slower.\n\n"
            "Use-case difference:\n"
            "RSA is used for secure key exchange, authentication, and digital signatures.\n"
            "AES is used for bulk data encryption, such as securing files, databases, or communication channels.\n\n"
            "In real-world systems, they are often combined:\n"
            "RSA encrypts the AES key, and AES encrypts the actual data — this is called hybrid encryption.\n",
            encoding="utf-8"
        )
        print("OK: rsa_vs_aes.txt Generated.")
    else:
        print("OK: rsa_vs_aes.txt Already Exists.")


# ---------- მთავარი ----------
def main():
    print("== OpenSSL File Encryption Lab (Task 1) ==")
    print("OpenSSL =", OPENSSL)
    # 0) OpenSSL ვერსია (სურვილისამებრ, დიაგნოსტიკა)
    run([OPENSSL, "version"])

    # 1) ტექსტი
    ensure_message()

    # 2) RSA გასაღებები
    ensure_rsa_keys()

    # 3) RSA Encrypt/Decrypt
    rsa_encrypt_decrypt()

    # 4) AES Encrypt/Decrypt
    ensure_aes_key_iv()
    aes_encrypt_decrypt()

    # 5) ტექსტური ახსნა
    write_rsa_vs_aes()

    print("\n✅ Done ! All files are Created Successfully.")


if __name__ == "__main__":
    main()

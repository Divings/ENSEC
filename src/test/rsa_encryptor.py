import os, sys, json, hashlib, sqlite3
from pathlib import Path
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from Crypto.Cipher import AES

# ===============================================
# 定数
# ===============================================
APPDATA = Path(os.getenv("APPDATA")) / "EncryptSecureDEC"
RSA_KEY_PATH = APPDATA / "key" / "private_key"   # 自分用秘密鍵
BLOCKCHAIN_HEADER = b'BLOCKCHAIN_DATA_START\n'
TRUSTED_DIR = APPDATA / "TrustedKeys"
DB_PATH = APPDATA / "settings.db"

# ===============================================
# 設定管理
# ===============================================
def _ensure_settings_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

def get_rsa_mode_enabled() -> bool:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            _ensure_settings_table(conn)
            cur = conn.execute("SELECT value FROM settings WHERE key=?", ("rsa_mode_enabled",))
            row = cur.fetchone()
            return row and row[0] == "1"
    except Exception as e:
        print(f"[WARN] get_rsa_mode_enabled: {e}", file=sys.stderr)
        return False

def set_rsa_mode_enabled(enabled: bool) -> None:
    try:
        with sqlite3.connect(DB_PATH) as conn:
            _ensure_settings_table(conn)
            conn.execute("""
                INSERT INTO settings(key, value) VALUES(?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """, ("rsa_mode_enabled", "1" if enabled else "0"))
            conn.commit()
    except Exception as e:
        print(f"[WARN] set_rsa_mode_enabled: {e}", file=sys.stderr)
from Key_Decryptor import load_private_key

# ===============================================
# 鍵処理
# ===============================================
def load_private():
    key = load_private_key()
    pem_data = key.export_key(format='PEM')  # PEMバイト列に変換
    crypto_key = serialization.load_pem_private_key(pem_data, password=None)
    return crypto_key

def load_rsa_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)

def rsa_encrypt_key(aes_key: bytes, pubkey):
    return pubkey.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
import traceback
def rsa_decrypt_key(enc_key: bytes, privkey):
    try:
        return privkey.decrypt(
            enc_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        messagebox.showerror("エラー","ファイルが破損しているか秘密鍵が一致しません")
        print(traceback.print_exc())
        return None

def list_available_public_keys():
    keys = []
    mypub = APPDATA / "key" / "public.pem"
    if mypub.exists():
        keys.append(("自分の公開鍵", str(mypub)))
    if TRUSTED_DIR.exists():
        for f in TRUSTED_DIR.glob("*.pem"):
            keys.append((f"Trusted: {f.stem}", str(f)))
    return keys

def choose_key_dialog(parent=None):
    keys = list_available_public_keys()
    if not keys:
        messagebox.showerror("鍵エラー", "利用可能な公開鍵が見つかりません", parent=parent)
        return None
    dlg = tk.Toplevel(parent)
    dlg.title("公開鍵を選択")
    dlg.geometry("400x120")
    dlg.grab_set()

    ttk.Label(dlg, text="暗号化に使用する公開鍵を選択してください").pack(pady=10)
    selected = tk.StringVar(value=keys[0][1])
    combo = ttk.Combobox(dlg, values=[name for name, _ in keys], state="readonly")
    combo.current(0)
    combo.pack(fill="x", padx=20)

    chosen = {"path": None}
    def ok():
        idx = combo.current()
        chosen["path"] = keys[idx][1]
        dlg.destroy()
    ttk.Button(dlg, text="OK", command=ok).pack(pady=10)
    dlg.wait_window()
    return chosen["path"]

# ===============================================
# RSA暗号化 / 復号
# ===============================================
def encrypt_with_blockchain(plaintext: bytes, user="unknown", memo="", parent=None) -> bytes:
    key_path = choose_key_dialog(parent)
    if not key_path:
        return None
    
    pubkey = load_rsa_key(key_path)
    if hasattr(pubkey, "public_key"):  # 秘密鍵を渡された場合
        pubkey = pubkey.public_key()

    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    enc_key = rsa_encrypt_key(aes_key, pubkey)
    file_hash = hashlib.sha256(ciphertext).hexdigest()

    #bc = Blockchain()
    #bc.add_block(Block("Encrypt", file_hash, user, memo))

    core = (
        len(enc_key).to_bytes(4, "big") +
        enc_key + nonce + ciphertext + tag
    )
    return core

from Crypto.Cipher import AES
import hashlib
from tkinter import messagebox

def decrypt_rsa_file(data: bytes, user="unknown", memo="") -> bytes:
    """
    RSAモードで暗号化されたファイルを復号する。
    ブロックチェーンは非対応。
    """
    try:
        # 先頭の鍵長
        klen = int.from_bytes(data[:4], "big")
    except Exception:
        messagebox.showerror("エラー", "ファイル形式が不正です")
        return None

    try:
        # 鍵・Nonce・Tag・Ciphertext の抽出
        enc_key = data[4:4+klen]
        pos = 4 + klen
        nonce = data[pos:pos+12]; pos += 12
        tag = data[-16:]
        ciphertext = data[pos:-16]

        # 秘密鍵読み込み
        privkey = load_private()

        # RSAでAES鍵復号
        aes_key = rsa_decrypt_key(enc_key, privkey)
        if aes_key == None:
            return None
        # AES-GCM復号
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        # 確認用: ハッシュ計算（任意）
        file_hash = hashlib.sha256(ciphertext).hexdigest()
        print(f"[INFO] Decrypted (hash={file_hash}, user={user}, memo={memo})")

        return plaintext

    except Exception as e:
        messagebox.showerror("復号エラー", f"復号に失敗しました: {e}")
        return None

from tkinter import filedialog
import getpass

def encrypt_file_with_dialog(file=None):
    """
    ファイル選択ダイアログを開き、選んだファイルをRSA暗号化する。
    - user は自動で OS ユーザー名を取得
    - memo_entry.get() を内部で呼び出してメモを取得
    - 出力ファイルは .vdec に保存
    """
    if file==None:
        file_path = filedialog.askopenfilename(title="暗号化するファイルを選択")
        if not file_path:
            return None
    else:
        file_path=os.path.abspath(file)
    with open(file_path, "rb") as f:
        plaintext = f.read()

    user = getpass.getuser()
    
    from pack import text_summary_window
    try:
        env_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if env_key:
            a = text_summary_window.summarize_text_file(file_path)
            if a == False or a == None:
                memo = memo_entry.get()
            else:
                memo = a
        else:
            memo = memo_entry.get()
    except Exception:
        memo = ""

    data = encrypt_with_blockchain(plaintext, user=user, memo=memo)
    if not data:
        return None

    out_path = file_path + ".rdec"
    with open(out_path, "wb") as out:
        out.write(data)

    return out_path


def decrypt_file_with_dialog(file_path=None):
    """
    ファイル選択ダイアログを開き、選んだ .vdec ファイルをRSA復号する。
    - user は自動で OS ユーザー名を取得
    - memo_entry.get() を内部で呼び出してメモを取得
    - 復号結果は元ファイル名に保存
    """
    if file_path==None:
        file_path = filedialog.askopenfilename(
            title="復号するファイルを選択",
            filetypes=[("RSA暗号ファイル", "*.rdec")]
        )
        if not file_path:
            return None
        
    with open(file_path, "rb") as f:
        blob = f.read()

    user = getpass.getuser()
    global memo_entry
    # メインウインドウの memo_entry を直接参照
    try:
        memo = memo_entry.get()
    except Exception:
        memo = ""
    try:
        plaintext = decrypt_rsa_file(blob, user=user, memo=memo)
        if plaintext == None:
            return
    except TypeError:
        return None
    if file_path.endswith(".rdec"):
        out_path = file_path[:-5]
    else:
        out_path = file_path + ".dec"
    try:
        with open(out_path, "wb") as out:
            out.write(plaintext)
    except TypeError:
        return None
    return out_path

# Copyright (c) 2025 Innovation Craft Inc. All Rights Reserved.
# 本ソフトウェアはプロプライエタリライセンスに基づき提供されています。

import base64
import configparser
import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

def show_info(title, message):
    messagebox.showinfo(title, message)

def show_error(title, message):
    messagebox.showerror(title, message)

import sys

from tkinter import filedialog

def _default_app_dir() -> str:
    base = os.getenv("APPDATA") or os.path.expanduser("~")
    folder = os.path.join(base, "EncryptSecureDEC")
    os.makedirs(folder, exist_ok=True)
    return folder

import os, sys, keyring
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


default_keys=_default_app_dir()+"\\key"


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password)

SERVICE = "EncryptSecureDEC"
USER = "master_user"

SALT_FILE = os.path.join(default_keys, "salt.bin")
ENCRYPTED_KEY_FILE = os.path.join(default_keys, "private_key.enc")
PLAIN_KEY_FILE = os.path.join(default_keys, "private.pem")


# --- 秘密鍵暗号化 ---
def encrypt_private_key(private_key_bytes: bytes):
    master_pw = keyring.get_password(SERVICE, USER)
    if master_pw is None:
        raise ValueError("❌ keyringにマスターパスワードが登録されていません。")

    # ソルト
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        salt = open(SALT_FILE, "rb").read()

    key = derive_key(master_pw.encode(), salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(private_key_bytes) + encryptor.finalize()

    with open(ENCRYPTED_KEY_FILE, "wb") as f:
        f.write(ciphertext)
    print(f"🔒 秘密鍵を暗号化して保存しました → {ENCRYPTED_KEY_FILE}")

# --- 平文の鍵を暗号化して削除 ---
def ensure_encrypted_key(private_key_path=None):
    if private_key_path!=None:
        PLAIN_KEY_FILE=private_key_path
    if os.path.exists(PLAIN_KEY_FILE):
        with open(PLAIN_KEY_FILE, "rb") as f:
            private_key_bytes = f.read()
        encrypt_private_key(private_key_bytes)
        os.remove(PLAIN_KEY_FILE)

# --- 鍵生成処理 ---
def generate_keys(private_key_path=None, public_key_path=None):
    try:
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        if private_key_path==None or public_key_path==None:
            key_dir = default_keys
        else:
            from pathlib import Path
            key_dir = Path(private_key_path).parent
        if private_key_path is None:
            private_key_path = os.path.join(default_keys, "private.pem")
        if public_key_path is None:
            public_key_path = os.path.join(default_keys, "public.pem")

        if not os.path.exists(default_keys):
            os.makedirs(key_dir)

        private_exists = os.path.exists(os.path.join(key_dir, "private.pem"))
        public_exists = os.path.exists(os.path.join(key_dir, "public.pem"))

        # 鍵が存在しない場合は新規生成
        if not private_exists and not public_exists:
            key = RSA.generate(2048)
            with open(private_key_path, "wb") as f:
                f.write(key.export_key())
            with open(public_key_path, "wb") as f:
                f.write(key.publickey().export_key())
            show_info("鍵生成", f"🔐 鍵ペアを生成しました。\n\n秘密鍵: {private_key_path}\n公開鍵: {public_key_path}")

        # 既存鍵があれば暗号化チェック
        ensure_encrypted_key(private_key_path)

    except Exception as e:
        show_error("エラー", f"鍵生成中にエラーが発生しました。\n{e}")

def get_signature_filename(file_path: str) -> str:
    return file_path + ".sig"

def regenerate_keys(private_key_path=None, public_key_path=None):
    try:
        import shutil
        shutil.rmtree(default_keys)
        generate_keys()

        #show_info("鍵再作成", f"🔑 鍵ペアを再作成しました。\n\n秘密鍵: {private_key_path}\n公開鍵: {public_key_path}")
    except Exception as e:
        show_error("エラー", f"鍵再作成中にエラーが発生しました。\n{e}")

def export_public_key():
    try:
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        pub_path = os.path.join(default_keys, "public.pem")

        if not os.path.exists(pub_path):
            show_error("エラー", "公開鍵が存在しません。先に鍵を生成してください。")
            return

        with open(pub_path, "rb") as f:
            pubkey_data = f.read()

        save_path = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if save_path:
            with open(save_path, "wb") as f:
                f.write(pubkey_data)
            show_info("エクスポート完了", f"公開鍵を保存しました：\n{save_path}")
    except Exception as e:
        show_error("エラー", f"公開鍵エクスポート中にエラーが発生しました。\n{e}")


import sys

def sign_file(file_path: str, private_key_path: str = None):
    try:
        # デフォルトの鍵パスを sys.argv[0] 基準で設定
        if private_key_path is None:
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            private_key_path = os.path.join(default_keys, "private_key.enc")  # ← 暗号化ファイルに変更

        signature_path = get_signature_filename(file_path)

         # Key_Decryptor.py から復号関数をインポート
        from Key_Decryptor import load_private_key

        # 復号してRSAオブジェクトを取得
        private_key = load_private_key()

        with open(file_path, "rb") as f:
            file_data = f.read()

        hash_obj = SHA256.new(file_data)
        signature = pkcs1_15.new(private_key).sign(hash_obj)

        with open(signature_path, "wb") as f:
            f.write(base64.b64encode(signature))

        show_info("署名成功", f"✅ 署名を保存しました。\n\nファイル: {signature_path}")
    except Exception as e:
        show_error("署名エラー", f"署名作成中にエラーが発生しました。\n{e}")


# ===== 署名検証（自分→TrustedKeys→任意選択） =====
import os, base64, hashlib
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# TrustedKeys の保存先（default_keys の兄弟ディレクトリとして作成）
def _trusted_dir() -> str:
    app_dir = os.path.dirname(default_keys)  # default_keys = .../EncryptSecureDEC/Key
    d = os.path.join(app_dir, "TrustedKeys")
    os.makedirs(d, exist_ok=True)
    return d

def _sha256_fp(pem_bytes: bytes) -> str:
    h = hashlib.sha256(pem_bytes).hexdigest()
    # 表示用に短縮（20バイト分）
    return ":".join(h[i:i+2] for i in range(0, 40, 2))

def _verify_with_pubkey_bytes(pub_pem: bytes, data: bytes, sig_raw: bytes) -> bool:
    try:
        h = SHA256.new(data)
        pkcs1_15.new(RSA.import_key(pub_pem)).verify(h, sig_raw)
        return True
    except (ValueError, TypeError):
        return False

def _load_my_public_key_bytes() -> bytes | None:
    try:
        with open(os.path.join(default_keys, "public.pem"), "rb") as f:
            return f.read()
    except Exception:
        return None

def _iter_trusted_public_keys_bytes():
    tdir = _trusted_dir()
    for fn in os.listdir(tdir):
        if fn.lower().endswith(".pem"):
            p = os.path.join(tdir, fn)
            try:
                with open(p, "rb") as f:
                    yield p, f.read()
            except Exception:
                continue

def import_public_key_from_path(path: str, parent=None) -> bool:
    path = filedialog.askopenfilename(
        parent=parent,
        title="公開鍵(.pem)を選択",
        filetypes=[("PEM 公開鍵", "*.pem"), ("すべてのファイル", "*.*")]
    )
    if not path:
        return False
    """指定パスの公開鍵を TrustedKeys に登録（重複は fingerprint で判定）"""
    try:
        with open(path, "rb") as f:
            pem = f.read()
        key = RSA.import_key(pem)
        if key.has_private():
            messagebox.showerror("エラー", "秘密鍵が含まれています。公開鍵のみをインポートしてください。", parent=parent)
            return False
        if key.size_in_bits() < 2048:
            messagebox.showerror("エラー", f"鍵長が短すぎます ({key.size_in_bits()} bit)。2048bit以上を推奨。", parent=parent)
            return False

        fp = _sha256_fp(key.export_key(format="PEM"))
        digest_new = hashlib.sha256(pem).digest()
        for _, pem2 in _iter_trusted_public_keys_bytes():
            if hashlib.sha256(pem2).digest() == digest_new:
                messagebox.showinfo("情報", "同じ公開鍵は既に登録されています。", parent=parent)
                return True

        # 元ファイル名をラベル代わりにしつつ、FP短縮を付与
        label = os.path.splitext(os.path.basename(path))[0]
        safe_label = "".join(c for c in label if c not in r'\/:*?"<>|').strip() or "key"
        short = fp.replace(":", "")[:16]
        out = os.path.join(_trusted_dir(), f"{safe_label}_{short}.pem")
        with open(out, "wb") as w:
            w.write(key.export_key(format="PEM"))

        messagebox.showinfo("完了", f"公開鍵をインポートしました。\nFP: {fp}\n保存先: {out}", parent=parent)
        return True
    except Exception as e:
        messagebox.showerror("エラー", f"公開鍵のインポートに失敗しました。\n{e}", parent=parent)
        return False

def verify_file_signature(file_path: str,
                          public_key_path: str | None = None,
                          parent_window=None,
                          allow_select_fallback: bool = True):
    """
    検証順序:
      1) public_key_path が指定されていればそれを使用
      2) 自分の公開鍵（default_keys/public.pem）
      3) TrustedKeys 配下の公開鍵で総当り
      4) (任意) ファイル選択で公開鍵を指定 → 成功時は TrustedKeys へ登録するか確認
    成功: return 1 / 失敗: return None（UIは show_info/show_error で通知）
    """
    try:
        signature_path = get_signature_filename(file_path)

        with open(file_path, "rb") as f:
            file_data = f.read()
        with open(signature_path, "rb") as f:
            signature_b64 = f.read()

        try:
            signature_raw = base64.b64decode(signature_b64)
        except Exception:
            show_error("署名エラー", "Base64デコード失敗：署名ファイルが破損しています。")
            return

        # 1) 明示された公開鍵パスを優先
        if public_key_path:
            try:
                with open(public_key_path, "rb") as f:
                    pub = f.read()
                if _verify_with_pubkey_bytes(pub, file_data, signature_raw):
                    show_info("検証成功",
                              f"署名は有効です。\n公開鍵: {public_key_path}\nFP: {_sha256_fp(pub)}")
                    return 1
            except Exception:
                pass  # 次へ

        # 2) 自分の公開鍵で検証
        my_pub = _load_my_public_key_bytes()
        if my_pub and _verify_with_pubkey_bytes(my_pub, file_data, signature_raw):
            show_info("検証成功", f"署名は有効です。\n署名者: 自分の公開鍵 (FP: {_sha256_fp(my_pub)})")
            return 1

        # 3) TrustedKeys 総当り
        for pem_path, pem in _iter_trusted_public_keys_bytes():
            if _verify_with_pubkey_bytes(pem, file_data, signature_raw):
                label = os.path.splitext(os.path.basename(pem_path))[0]
                show_info("検証成功", f"署名は有効です。\n署名者: {label}\nFP: {_sha256_fp(pem)}")
                return 1

        # 4) Fallback：その場で公開鍵を選択
        if allow_select_fallback and messagebox.askyesno(
            "公開鍵が見つかりません",
            "登録済みの公開鍵では検証できませんでした。\n公開鍵ファイルを選択して検証しますか？",
            parent=parent_window
        ):
            path = filedialog.askopenfilename(
                parent=parent_window,
                title="検証に使う公開鍵(.pem)を選択",
                filetypes=[("PEM 公開鍵", "*.pem"), ("すべてのファイル", "*.*")]
            )
            if path:
                try:
                    with open(path, "rb") as f:
                        pem = f.read()
                    if _verify_with_pubkey_bytes(pem, file_data, signature_raw):
                        fp = _sha256_fp(pem)
                        if messagebox.askyesno(
                            "検証成功",
                            f"署名は有効です。\n鍵: {os.path.basename(path)}\nFP: {fp}\n\nこの公開鍵を信頼済みに追加しますか？",
                            parent=parent_window
                        ):
                            import_public_key_from_path(path, parent=parent_window)
                        else:
                            show_info("検証成功", f"署名は有効です。\n鍵: {os.path.basename(path)}\nFP: {fp}")
                        return 1
                except Exception as e:
                    show_error("検証エラー", f"公開鍵の読み込みに失敗しました。\n{e}")

        # ここまで来たら失敗
        show_error("検証失敗", "署名の検証に失敗しました。\n公開鍵が未登録か、ファイル/署名が改ざんされています。")

    except (ValueError, TypeError):
        show_error("検証失敗", "署名が改ざんされているか、ファイルが変更されています。")
    except Exception as e:
        show_error("検証エラー", f"検証中にエラーが発生しました。\n{e}")

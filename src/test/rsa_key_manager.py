import os
import shutil
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# =====================================================
# 基本パス
# =====================================================
APPDATA = Path(os.getenv("APPDATA", ".")) / "EncryptSecureDEC"
PERSONAL_DIR = APPDATA / "Cryptos-key"
CORP_DIR     = APPDATA / "corp_key"
TRUSTED_PUB  = APPDATA / "TrustedKeys"

# =====================================================
# RSA鍵生成（既存 ensure_rsa_keypair と完全互換）
# =====================================================
def generate_rsa_keypair(private_path: Path, public_path: Path):
    if private_path.exists() and public_path.exists():
        return

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(priv_pem)

    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_path.write_bytes(pub_pem)

# =====================================================
# 鍵存在チェック
# =====================================================
def has_valid_keypair(base_dir: Path) -> bool:
    return (
        (base_dir / "private.pem").exists() and
        (base_dir / "public.pem").exists()
    )

# =====================================================
# 初期鍵生成（★自動コピー込み・関数分割なし）
# =====================================================
def ensure_default_keys():
    """
    ・個人用 / 法人用をチェック
    ・不足分のみ生成
    ・生成した公開鍵はその場で trusted_pub に自動コピー
    ・既存鍵は再生成・再コピーしない
    """
    APPDATA.mkdir(parents=True, exist_ok=True)
    TRUSTED_PUB.mkdir(parents=True, exist_ok=True)

    # ---------- 個人用 ----------
    if not has_valid_keypair(PERSONAL_DIR):
        priv = PERSONAL_DIR / "private.pem"
        pub  = PERSONAL_DIR / "public.pem"

        generate_rsa_keypair(priv, pub)

        dst = TRUSTED_PUB / "personal_public.pem"
        if not dst.exists():
            shutil.copy2(pub, dst)

    # ---------- 法人用 ----------
    if not has_valid_keypair(CORP_DIR):
        priv = CORP_DIR / "private.pem"
        pub  = CORP_DIR / "public.pem"

        generate_rsa_keypair(priv, pub)

        dst = TRUSTED_PUB / "corporate_public.pem"
        if not dst.exists():
            shutil.copy2(pub, dst)

# =====================================================
# 公開鍵選択（暗号化用）
# =====================================================
def choose_trusted_public_key() -> str | None:
    keys = sorted(TRUSTED_PUB.glob("*.pem"))
    if not keys:
        return None

    selected = {"path": None}

    win = tk.Toplevel()
    win.title("公開鍵を選択")
    try:
        win.iconbitmap('resources/IMG_8776.ICO')
    except:
        pass
    tk.Label(win, text="使用する公開鍵を選択してください").pack(padx=10, pady=5)

    listbox = tk.Listbox(win, width=50, height=8)
    for k in keys:
        listbox.insert(tk.END, k.name)
    listbox.pack(padx=10, pady=5)

    def ok():
        idx = listbox.curselection()
        if idx:
            selected["path"] = str(keys[idx[0]])
            win.destroy()

    def cancel():
        win.destroy()
        return None

    listbox.bind("<Double-Button-1>", lambda e: ok())

    btn = tk.Frame(win)
    btn.pack(pady=5)

    tk.Button(btn, text="OK", width=10, command=ok).pack(side=tk.LEFT, padx=5)
    tk.Button(btn, text="キャンセル", width=10, command=cancel).pack(side=tk.LEFT)

    win.grab_set()
    win.wait_window()

    return selected["path"]

# =====================================================
# 秘密鍵選択（復号用）
# =====================================================
def choose_private_key_path() -> str | None:
    keys = []
    key_dirs=[CORP_DIR,PERSONAL_DIR]
    for d in key_dirs:
        keys.extend(sorted(d.glob("private.pem")))

    if not keys:
        return None

    selected = {"path": None}

    win = tk.Toplevel()
    win.title("秘密鍵を選択")
    try:
        win.iconbitmap('resources/IMG_8776.ICO')
    except:
        pass
    
    tk.Label(win, text="復号に使用する秘密鍵を選択してください").pack(padx=10, pady=5)

    listbox = tk.Listbox(win, width=50, height=8)
    for k in keys:
        listbox.insert(tk.END, f"{k.parent.name} / {k.name}")
    listbox.pack(padx=10, pady=5)

    def ok():
        idx = listbox.curselection()
        if idx:
            selected["path"] = str(keys[idx[0]])
            win.destroy()

    def cancel():
        
        win.destroy()
        return None

    listbox.bind("<Double-Button-1>", lambda e: ok())

    btn = tk.Frame(win)
    btn.pack(pady=5)

    tk.Button(btn, text="OK", width=10, command=ok).pack(side=tk.LEFT, padx=5)
    tk.Button(btn, text="キャンセル", width=10, command=cancel).pack(side=tk.LEFT)

    win.grab_set()
    win.wait_window()

    return selected["path"]
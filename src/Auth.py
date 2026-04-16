from ctypes import CDLL, c_int, c_char_p
import json
import os
import sys

# ====== runtime guard ======
LIB_PATH = os.path.join("/usr/lib64", "libanv_core.so")
EXPECTED_VERSION = "2.5.0"

lib = CDLL(LIB_PATH)

lib.anv_is_allowed_runtime.restype = c_int
lib.anv_get_last_reason.restype = c_char_p
lib.anv_get_last_details_json.restype = c_char_p

# 追加: バージョン取得API
lib.anv_get_version_major.restype = c_int
lib.anv_get_version_minor.restype = c_int
lib.anv_get_version_patch.restype = c_int
lib.anv_get_version_hex.restype = c_int
lib.anv_get_version_string.restype = c_char_p


def get_library_version():
    version_str = lib.anv_get_version_string().decode("utf-8", errors="replace")
    major = lib.anv_get_version_major()
    minor = lib.anv_get_version_minor()
    patch = lib.anv_get_version_patch()
    version_hex = lib.anv_get_version_hex()

    return {
        "string": version_str,
        "major": major,
        "minor": minor,
        "patch": patch,
        "hex": version_hex,
    }


def authorize_environment():
    allowed = bool(lib.anv_is_allowed_runtime())
    reason = lib.anv_get_last_reason().decode("utf-8", errors="replace")
    details_raw = lib.anv_get_last_details_json().decode("utf-8", errors="replace")

    try:
        details = json.loads(details_raw)
    except Exception:
        details = {"raw": details_raw}

    version_info = get_library_version()

    # runtime 不許可
    if not allowed:
        return {
            "ok": False,
            "reason": reason,
            "details": details,
            "version": version_info,
        }

    # バージョン不一致
    if version_info["string"] != EXPECTED_VERSION:
        return {
            "ok": False,
            "reason": "library_version_mismatch",
            "details": details,
            "version": version_info,
            "expected_version": EXPECTED_VERSION,
        }

    return {
        "ok": True,
        "reason": None,
        "details": details,
        "version": version_info,
    }

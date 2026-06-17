import os
import shutil
import logging
import time
import tempfile
import base64
import hashlib
import json

from Crypto.Cipher import AES

import config
from log_utils import log_event

logger = logging.getLogger(__name__)

PAGE_SIZE = 4096
V3_PBKDF2_SALT = b"666DingTalk888"[:8]
V3_PBKDF2_ITERATIONS = 1000
V3_PBKDF2_KEYLEN = 32


def copy_encrypted_db(retry_count=None, retry_delay=None):
    """Copy encrypted database files to a temp directory to avoid lock conflicts."""
    if retry_count is None:
        retry_count = config.COPY_RETRY_COUNT
    if retry_delay is None:
        retry_delay = config.COPY_RETRY_DELAY

    temp_dir = tempfile.mkdtemp(prefix="dingtalk_encrypt_", dir=config.DECRYPTED_DIR)
    dest_db = os.path.join(temp_dir, "dingtalk_encrypted.db")

    if not os.path.isfile(config.ENCRYPTED_DB):
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise FileNotFoundError(
            f"未找到钉钉加密数据库: {config.ENCRYPTED_DB}\n"
            "请确认钉钉桌面客户端已登录，并检查自动检测到的数据目录是否正确。"
        )

    # Files to copy: main db + wal + shm
    files_to_copy = [
        (config.ENCRYPTED_DB, dest_db),
        (config.ENCRYPTED_DB + "-wal", dest_db + "-wal"),
        (config.ENCRYPTED_DB + "-shm", dest_db + "-shm"),
    ]

    for attempt in range(retry_count):
        try:
            copied_files = []
            for src, dst in files_to_copy:
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    copied_files.append(os.path.basename(src))

            if not os.path.isfile(dest_db):
                raise FileNotFoundError(
                    f"复制失败，未能从 {config.ENCRYPTED_DB} 生成临时数据库文件。"
                )

            log_event(
                logger,
                "info",
                "decrypt.copy_succeeded",
                temp_dir=temp_dir,
                files=copied_files,
            )
            return dest_db
        except (PermissionError, OSError) as e:
            log_event(
                logger,
                "warning",
                "decrypt.copy_retry_failed",
                attempt=attempt + 1,
                retry_count=retry_count,
                error=e,
            )
            if attempt < retry_count - 1:
                time.sleep(retry_delay)
            else:
                # Clean up partial copy
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise RuntimeError(
                    f"复制钉钉加密数据库失败，已重试 {retry_count} 次：{e}"
                )

    shutil.rmtree(temp_dir, ignore_errors=True)
    raise RuntimeError("复制钉钉加密数据库失败。")


def _generate_v2_key(user_uid):
    md5_hex = hashlib.md5(user_uid.encode("utf-8")).hexdigest()
    return md5_hex[:16].encode("ascii")


def _load_v3_salt(data_dir):
    config_path = os.path.join(data_dir, "user_config")
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"未找到钉钉 V3 user_config 文件: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        encoded = f.read().strip()

    try:
        payload = base64.b64decode(encoded).decode("utf-8")
        data = json.loads(payload)
    except Exception as e:  # pragma: no cover - depends on local file shape
        raise RuntimeError(f"解析钉钉 V3 user_config 失败: {e}") from e

    salt = (data.get("salt") or "").strip()
    if not salt:
        raise RuntimeError("钉钉 V3 user_config 中缺少 salt 字段。")
    log_event(
        logger,
        "info",
        "decrypt.v3_user_config_loaded",
        path=config_path,
        salt_len=len(salt),
        salt_prefix=salt[:6],
    )
    return salt


def _generate_v3_key(user_uid, data_dir):
    salt = _load_v3_salt(data_dir)
    pbkdf2_output = hashlib.pbkdf2_hmac(
        "sha1",
        (user_uid + salt).encode("utf-8"),
        V3_PBKDF2_SALT,
        V3_PBKDF2_ITERATIONS,
        V3_PBKDF2_KEYLEN,
    )
    md5_hex = hashlib.md5(pbkdf2_output).hexdigest()
    return md5_hex[:16].encode("ascii")


def _build_database_key():
    if config.DINGTALK_DATA_DIR.endswith("_v3"):
        log_event(
            logger,
            "info",
            "decrypt.mode_selected",
            mode="v3",
            uid_masked=config.get_runtime_diagnostics()["user_uid_masked"],
            data_dir=config.DINGTALK_DATA_DIR,
        )
        return _generate_v3_key(config.USER_UID, config.DINGTALK_DATA_DIR)
    log_event(
        logger,
        "info",
        "decrypt.mode_selected",
        mode="v2",
        uid_masked=config.get_runtime_diagnostics()["user_uid_masked"],
        data_dir=config.DINGTALK_DATA_DIR,
    )
    return _generate_v2_key(config.USER_UID)


def _decrypt_page_in_place(block, page):
    for offset in range(0, len(page), block.block_size):
        page[offset:offset + block.block_size] = block.decrypt(
            bytes(page[offset:offset + block.block_size])
        )


def _decrypt_database_pages(input_path, output_path, key):
    block = AES.new(key, AES.MODE_ECB)

    with open(input_path, "rb") as src, open(output_path, "wb") as dst:
        while True:
            page = bytearray(src.read(PAGE_SIZE))
            if not page:
                break

            if len(page) == PAGE_SIZE:
                _decrypt_page_in_place(block, page)

            dst.write(page)


def _validate_decrypted_header(output_path):
    with open(output_path, "rb") as f:
        header = f.read(16)
    if header != b"SQLite format 3\x00":
        log_event(
            logger,
            "warning",
            "decrypt.header_mismatch",
            path=output_path,
            header_hex=header.hex(),
            header_ascii="".join(chr(b) if 32 <= b <= 126 else "." for b in header),
        )
        raise RuntimeError(
            "解密失败：输出文件不是有效的 SQLite 数据库。"
            "请确认自动识别到的 DingTalk UID 和数据目录是否正确。"
        )


def decrypt_database(encrypted_db_path=None, output_path=None):
    """Decrypt the copied DingTalk database into a plain SQLite file."""

    if encrypted_db_path is None:
        encrypted_db_path = copy_encrypted_db()
    if output_path is None:
        output_path = config.DECRYPTED_DB_PATH
    if not os.path.isfile(encrypted_db_path):
        raise FileNotFoundError(f"待解密数据库不存在: {encrypted_db_path}")

    # Remove any stale output file from earlier failed attempts.
    if os.path.exists(output_path):
        os.remove(output_path)

    log_event(
        logger,
        "info",
        "decrypt.started",
        source_db=encrypted_db_path,
        target_db=output_path,
        source_size_mb=round(os.path.getsize(encrypted_db_path) / 1024 / 1024, 1),
        mode="v3" if config.DINGTALK_DATA_DIR.endswith("_v3") else "v2",
    )

    try:
        key = _build_database_key()
        _decrypt_database_pages(encrypted_db_path, output_path, key)
        _validate_decrypted_header(output_path)

        output_size = os.path.getsize(output_path)
        if output_size <= 0:
            raise RuntimeError(
                "解密失败：输出的数据库文件为空。"
                "请确认自动识别到的 DingTalk 数据目录和 UID 是否正确。"
            )
        log_event(
            logger,
            "info",
            "decrypt.completed",
            output_db=output_path,
            output_size_mb=round(output_size / 1024 / 1024, 1),
        )

        return output_path

    finally:
        # Clean up the encrypted copy
        if encrypted_db_path and os.path.dirname(encrypted_db_path) != config.ENCRYPTED_DB_DIR:
            temp_dir = os.path.dirname(encrypted_db_path)
            shutil.rmtree(temp_dir, ignore_errors=True)
            log_event(logger, "info", "decrypt.temp_dir_cleaned", path=temp_dir)


def sync_decrypt():
    """Full sync: copy encrypted DB, decrypt, return path to decrypted DB."""
    log_event(logger, "info", "decrypt.sync_started")
    encrypted_copy = copy_encrypted_db()
    decrypted_path = decrypt_database(encrypted_copy)
    log_event(logger, "info", "decrypt.sync_completed", output_db=decrypted_path)
    return decrypted_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    path = sync_decrypt()
    print(f"解密后的数据库已生成：{path}")

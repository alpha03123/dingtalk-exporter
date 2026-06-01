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

            logger.info(
                f"Successfully copied encrypted database to {temp_dir} "
                f"(files: {', '.join(copied_files)})"
            )
            return dest_db
        except (PermissionError, OSError) as e:
            logger.warning(f"Copy attempt {attempt + 1}/{retry_count} failed: {e}")
            if attempt < retry_count - 1:
                time.sleep(retry_delay)
            else:
                # Clean up partial copy
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise RuntimeError(
                    f"Failed to copy encrypted database after {retry_count} attempts: {e}"
                )

    shutil.rmtree(temp_dir, ignore_errors=True)
    raise RuntimeError("Failed to copy encrypted database")


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
        logger.info(f"Using native V3 decrypt key path for UID={config.USER_UID}")
        return _generate_v3_key(config.USER_UID, config.DINGTALK_DATA_DIR)
    logger.info(f"Using native V2 decrypt key path for UID={config.USER_UID}")
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

    logger.info(f"Starting decryption: {encrypted_db_path} -> {output_path}")

    try:
        key = _build_database_key()
        _decrypt_database_pages(encrypted_db_path, output_path, key)
        _validate_decrypted_header(output_path)

        output_size = os.path.getsize(output_path)
        if output_size <= 0:
            raise RuntimeError(
                "Decryption failed: output database is empty. "
                "Please verify the detected DingTalk data directory and UID."
            )
        logger.info(f"Decryption complete. Output size: {output_size / 1024 / 1024:.1f} MB")

        return output_path

    finally:
        # Clean up the encrypted copy
        if encrypted_db_path and os.path.dirname(encrypted_db_path) != config.ENCRYPTED_DB_DIR:
            temp_dir = os.path.dirname(encrypted_db_path)
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temp directory: {temp_dir}")


def sync_decrypt():
    """Full sync: copy encrypted DB, decrypt, return path to decrypted DB."""
    logger.info("=== Starting sync decrypt ===")
    encrypted_copy = copy_encrypted_db()
    decrypted_path = decrypt_database(encrypted_copy)
    logger.info("=== Sync decrypt complete ===")
    return decrypted_path


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    path = sync_decrypt()
    print(f"Decrypted database: {path}")

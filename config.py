import logging
import os
import re
import sys

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

logger = logging.getLogger(__name__)


def _load_redirected_dingtalk_bases():
    """Read any DingTalk app-data redirection targets configured by the client."""
    bases = []
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return bases

    redirect_file = os.path.join(appdata, "DingTalk", "redirectAppData.dat")
    if not os.path.isfile(redirect_file):
        return bases

    try:
        with open(redirect_file, "r", encoding="utf-8") as f:
            redirected = f.read().strip().strip("\x00")
    except OSError as e:
        logger.warning(f"Failed to read DingTalk redirect file {redirect_file}: {e}")
        return bases

    if redirected and os.path.isdir(redirected):
        bases.append(os.path.normpath(redirected))
        logger.info(f"Detected redirected DingTalk data dir: {redirected}")

    return bases


def _detect_v3_numeric_uid(data_dir, fallback_uid):
    """Try to resolve the real numeric UID used by DingTalk V3 databases.

    V3 folder names are not always the same as the chat-database UID. In
    practice, the real UID is commonly surfaced in local client logs.
    """
    base_dir = os.path.dirname(os.path.normpath(data_dir))
    log_dir = os.path.join(base_dir, "log")
    if not os.path.isdir(log_dir):
        return fallback_uid

    patterns = [
        re.compile(r"uid=(\d{10})"),
        re.compile(r"myOpenId=(\d{10})"),
        re.compile(r"cid=(\d{10}):"),
    ]
    scores = {}

    try:
        log_names = sorted(
            name for name in os.listdir(log_dir)
            if name.startswith(("cef_debug.log", "gaea.log"))
        )[-12:]
    except OSError as e:
        logger.warning(f"Failed to inspect DingTalk log dir {log_dir}: {e}")
        return fallback_uid

    for name in log_names:
        path = os.path.join(log_dir, name)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue

        for pattern in patterns:
            for match in pattern.finditer(text):
                uid = match.group(1)
                scores[uid] = scores.get(uid, 0) + 1

    if not scores:
        return fallback_uid

    uid, _ = max(scores.items(), key=lambda item: (item[1], item[0]))
    if uid != fallback_uid:
        logger.info(f"Resolved DingTalk V3 numeric UID from logs: {uid}")
    return uid


def _detect_dingtalk_user():
    """Auto-detect DingTalk user data directory and UID.

    Scans multiple possible DingTalk data directories for *_v2 (or *_v3) folders.
    Returns (data_dir, uid) or (None, None) if not found.

    Override with environment variables:
      DINGTALK_UID       — your DingTalk user UID
      DINGTALK_DATA_DIR  — full path to the *_v2 directory
    """
    # Environment variables take highest priority
    env_uid = os.environ.get("DINGTALK_UID", "").strip()
    env_dir = os.environ.get("DINGTALK_DATA_DIR", "").strip()

    if env_uid and env_dir:
        logger.info(f"Using config from environment: UID={env_uid}")
        return env_dir, env_uid

    # Multiple possible DingTalk base directories (ordered by likelihood)
    search_bases = []
    appdata = os.environ.get("APPDATA", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")

    if appdata:
        search_bases.append(os.path.join(appdata, "DingTalk"))
    if local_appdata and local_appdata != appdata:
        search_bases.append(os.path.join(local_appdata, "DingTalk"))
    if userprofile:
        search_bases.append(os.path.join(userprofile, "AppData", "Roaming", "DingTalk"))
        search_bases.append(os.path.join(userprofile, "AppData", "Local", "DingTalk"))
        search_bases.append(os.path.join(userprofile, "DingTalk"))
    search_bases.extend(_load_redirected_dingtalk_bases())

    # macOS and Linux paths
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        search_bases.append(os.path.join(home, "Library", "Application Support", "DingTalk"))
    elif sys.platform.startswith("linux"):
        search_bases.append(os.path.join(home, ".config", "DingTalk"))
        search_bases.append(os.path.join(home, ".local", "share", "DingTalk"))

    # Deduplicate while preserving order
    seen = set()
    unique_bases = []
    for b in search_bases:
        b_norm = os.path.normcase(os.path.normpath(b))
        if b_norm not in seen:
            seen.add(b_norm)
            unique_bases.append(b)
    search_bases = unique_bases

    # Find all *_v2 / *_v3 user directories that have a database file
    v2_dirs = []
    for dingtalk_base in search_bases:
        if not os.path.isdir(dingtalk_base):
            continue
        for entry in os.listdir(dingtalk_base):
            if entry.endswith(("_v2", "_v3")):
                full_path = os.path.join(dingtalk_base, entry)
                if os.path.isdir(full_path):
                    db_file = os.path.join(full_path, "DBFiles", "dingtalk.db")
                    if os.path.exists(db_file):
                        uid = entry.rsplit("_v", 1)[0]
                        if entry.endswith("_v3"):
                            uid = _detect_v3_numeric_uid(full_path, uid)
                        mtime = os.path.getmtime(db_file)
                        v2_dirs.append((uid, full_path, mtime))

    if not v2_dirs:
        return None, None

    if len(v2_dirs) == 1:
        uid, path, _ = v2_dirs[0]
        logger.info(f"Auto-detected DingTalk user: UID={uid}")
        return path, uid

    # Multiple users: pick the one with most recently modified database
    v2_dirs.sort(key=lambda x: x[2], reverse=True)
    uid, path, _ = v2_dirs[0]
    all_uids = [f"  UID={u} (path={p})" for u, p, _ in v2_dirs]
    logger.warning(
        f"Multiple DingTalk users found, using the most recent (UID={uid}):\n"
        + "\n".join(all_uids)
        + "\nTo use a different user, set DINGTALK_UID and DINGTALK_DATA_DIR environment variables."
    )
    return path, uid


def _detect_dingwave():
    """Auto-detect the dingwave binary in the tools/ directory.

    Checks multiple possible filenames to handle:
    - Platform differences (dingwave.exe vs dingwave)
    - Users who rename or download with different names
    """
    tools_dir = os.path.join(PROJECT_DIR, "tools")
    candidates = []

    if sys.platform == "win32":
        candidates = ["dingwave.exe", "dingwave"]
    else:
        candidates = ["dingwave", "dingwave.exe"]

    # Check exact names first
    for name in candidates:
        full = os.path.join(tools_dir, name)
        if os.path.isfile(full):
            return full

    # Fallback: find any executable-like file in tools/ with 'dingwave' in name
    if os.path.isdir(tools_dir):
        for f in os.listdir(tools_dir):
            lower = f.lower()
            if "dingwave" in lower and not lower.endswith((".md", ".txt", ".zip", ".tar", ".gz")):
                full = os.path.join(tools_dir, f)
                if os.path.isfile(full):
                    logger.info(f"Found dingwave binary: {f}")
                    return full

    # Return default (will fail later with clear message)
    return os.path.join(tools_dir, candidates[0])


# --- DingTalk data paths ---
# Auto-detection is tried first. If it fails (e.g. DingTalk not installed),
# set environment variables or edit the defaults below.
#
# Environment variables (recommended for override):
#   DINGTALK_UID       = your user UID (the number in the _v2 folder name)
#   DINGTALK_DATA_DIR  = full path to your DingTalk data directory
#
# Manual defaults (fallback when auto-detection and env vars both fail):
_detected_dir, _detected_uid = _detect_dingtalk_user()

DINGTALK_DATA_DIR = _detected_dir or r"C:\Users\<YOUR_USERNAME>\AppData\Roaming\DingTalk\<YOUR_UID>_v2"
USER_UID = _detected_uid or "<YOUR_UID>"

ENCRYPTED_DB_DIR = os.path.join(DINGTALK_DATA_DIR, "DBFiles")
ENCRYPTED_DB = os.path.join(ENCRYPTED_DB_DIR, "dingtalk.db")

# dingwave tool — auto-detected
DINGWAVE_PATH = _detect_dingwave()

# Sync settings
SYNC_INTERVAL_HOURS = 4
COPY_RETRY_COUNT = 3
COPY_RETRY_DELAY = 30  # seconds

# Data directories
DATA_DIR = os.path.join(PROJECT_DIR, "data")
DECRYPTED_DIR = os.path.join(DATA_DIR, "decrypted")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")
LOGS_DIR = os.path.join(PROJECT_DIR, "logs")

# File paths
DECRYPTED_DB_PATH = os.path.join(DECRYPTED_DIR, "dingtalk.db")
SYNC_STATE_FILE = os.path.join(DATA_DIR, "sync_state.json")

# Attachment directories (relative to DINGTALK_DATA_DIR)
ATTACHMENT_DIRS = {
    "image": "ImageFiles",
    "audio": "AudioFiles",
    "video": "VideoFiles",
    "resource_cache": "resource_cache",
}

# Message content types
CONTENT_TYPE_TEXT = 1
CONTENT_TYPE_IMAGE = 2
CONTENT_TYPE_VOICE = 300
CONTENT_TYPE_FILE = 501
CONTENT_TYPE_RICH_TEXT = 1200
CONTENT_TYPE_INTERACTIVE_CARD = 2900
CONTENT_TYPE_MINI_APP_CARD = 2950
CONTENT_TYPE_QUOTE = 3100
CONTENT_TYPE_VIDEO_CALL = 1101
CONTENT_TYPE_APPROVAL = 1400

# Content type names for display
CONTENT_TYPE_NAMES = {
    1: "文本",
    2: "图片",
    4: "文件",
    102: "系统消息",
    104: "系统通知",
    202: "链接",
    300: "语音",
    400: "视频",
    500: "位置",
    501: "文件",
    503: "文件",
    1101: "通话",
    1200: "富文本",
    1201: "交互卡片",
    1202: "系统提示",
    1400: "审批",
    1500: "任务",
    1600: "日程",
    2900: "互动卡片",
    2950: "小程序卡片",
    3100: "引用消息",
}

# Web server settings
# WEB_HOST = "0.0.0.0"
WEB_HOST = "localhost"
WEB_PORT = 8090

# Ensure directories exist
for d in [DATA_DIR, DECRYPTED_DIR, EXPORT_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

"""Read-only stdio MCP server for locally cached DingTalk messages."""

from datetime import date, datetime, time
from typing import Any

from mcp.server.fastmcp import FastMCP

import config
from decrypt import sync_decrypt
from parser import (
    DatabaseNotReadyError,
    get_connection,
    get_conversations,
    get_database_status,
    get_latest_message_time,
    get_messages,
    search_messages,
)
from scheduler import get_sync_state


mcp = FastMCP("dingtalk-exporter")


def _with_connection(callback):
    try:
        connection = get_connection()
    except DatabaseNotReadyError as error:
        raise RuntimeError(str(error)) from error
    try:
        return callback(connection)
    finally:
        connection.close()


def _message(message: dict[str, Any], chat_name: str = "") -> dict[str, str]:
    return {
        "message_id": str(message.get("id", "")),
        "time": message.get("created_at_str", ""),
        "speaker": message.get("sender_name", "") or "未知",
        "content_type": message.get("content_type_name", "未知"),
        "content": message.get("text", "") or message.get("content_type_name", "[无文本内容]"),
        "chat_id": message.get("cid", ""),
        "chat_name": chat_name,
    }


def _to_milliseconds(value: str, end: bool) -> int:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise ValueError("日期必须为 YYYY-MM-DD") from error
    clock = time.max if end else time.min
    return int(datetime.combine(parsed, clock).timestamp() * 1000)


def _conversations(connection, limit: int = 500) -> list[dict[str, Any]]:
    return get_conversations(connection, limit=limit, offset=0).get("conversations", [])


def _resolve_chat(connection, chat_id_or_name: str) -> dict[str, Any]:
    value = chat_id_or_name.strip()
    if not value:
        raise ValueError("chat_id_or_name 不能为空")

    all_chats = _conversations(connection)
    exact_id = [chat for chat in all_chats if chat["cid"] == value]
    if len(exact_id) == 1:
        return exact_id[0]

    matches = [chat for chat in all_chats if chat["title"] == value]
    if not matches:
        matches = [chat for chat in all_chats if value.lower() in chat["title"].lower()]
    if len(matches) != 1:
        candidates = [{"chat_id": chat["cid"], "chat_name": chat["title"]} for chat in matches[:20]]
        raise ValueError(f"群聊匹配数量为 {len(matches)}，请使用 chat_id。候选：{candidates}")
    return matches[0]


@mcp.tool()
def dingtalk_health() -> dict[str, Any]:
    """Return local DingTalk database readiness and latest cached-message time."""
    status = get_database_status()
    result: dict[str, Any] = {
        "database_ready": status["ready"],
        "is_v3": config.DINGTALK_DATA_DIR.endswith("_v3"),
        "is_syncing": get_sync_state().get("is_syncing", False),
    }
    if status["ready"]:
        result["latest_message_time"] = _with_connection(get_latest_message_time)
    else:
        result["error"] = status["error"]
    return result


@mcp.tool()
def dingtalk_sync() -> dict[str, Any]:
    """Refresh the local decrypted database from the DingTalk DB and WAL files."""
    sync_decrypt()
    return dingtalk_health()


@mcp.tool()
def dingtalk_list_chats(query: str = "", limit: int = 100, offset: int = 0) -> dict[str, Any]:
    """List locally cached DingTalk conversations, optionally filtering by name."""
    if not 1 <= limit <= 500:
        raise ValueError("limit 必须在 1 到 500 之间")
    if offset < 0:
        raise ValueError("offset 不能小于 0")

    def query_chats(connection):
        result = get_conversations(connection, limit=limit, offset=offset, keyword=query or None)
        return {
            "total": result["total"],
            "conversations": [
                {
                    "chat_id": chat["cid"],
                    "chat_name": chat["title"],
                    "type": chat["type"],
                    "member_count": chat["member_count"],
                    "last_modify": chat["last_modify"],
                }
                for chat in result["conversations"]
            ],
        }

    return _with_connection(query_chats)


@mcp.tool()
def dingtalk_find_chats(query: str, limit: int = 20) -> dict[str, Any]:
    """Find DingTalk conversations by name before retrieving their history."""
    return dingtalk_list_chats(query=query, limit=limit)


@mcp.tool()
def dingtalk_get_chat_history(
    chat_id_or_name: str,
    start_time: str,
    end_time: str,
    limit: int = 1000,
    cursor: int = 0,
) -> dict[str, Any]:
    """Get one conversation's cached messages for an inclusive date range.

    ``cursor`` is the number of newest matching messages already read; use the
    returned ``next_cursor`` to request the next older page.
    """
    if not 1 <= limit <= 1000:
        raise ValueError("limit 必须在 1 到 1000 之间")
    if cursor < 0:
        raise ValueError("cursor 不能小于 0")
    since = _to_milliseconds(start_time, end=False)
    until = _to_milliseconds(end_time, end=True)
    if since > until:
        raise ValueError("start_time 不能晚于 end_time")

    def history(connection):
        chat = _resolve_chat(connection, chat_id_or_name)
        result = get_messages(
            connection,
            chat["cid"],
            limit=limit,
            offset=cursor,
            since_time=since,
            until_time=until,
        )
        returned = len(result["messages"])
        next_cursor = cursor + returned
        return {
            "chat_id": chat["cid"],
            "chat_name": chat["title"],
            "total": result["total"],
            "messages": [_message(message, chat["title"]) for message in result["messages"]],
            "next_cursor": next_cursor if next_cursor < result["total"] else None,
        }

    return _with_connection(history)


@mcp.tool()
def dingtalk_search_messages(query: str, limit: int = 100, offset: int = 0) -> dict[str, Any]:
    """Search locally cached message text across DingTalk conversations."""
    if not query.strip():
        raise ValueError("query 不能为空")
    if not 1 <= limit <= 200:
        raise ValueError("limit 必须在 1 到 200 之间")
    if offset < 0:
        raise ValueError("offset 不能小于 0")

    def search(connection):
        chats = {chat["cid"]: chat["title"] for chat in _conversations(connection)}
        messages = search_messages(connection, query, limit=limit, offset=offset)
        return {
            "query": query,
            "messages": [_message(message, chats.get(message.get("cid", ""), "")) for message in messages],
        }

    return _with_connection(search)


if __name__ == "__main__":
    mcp.run(transport="stdio")

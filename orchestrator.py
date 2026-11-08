"""
orchestrator.py
Python 3.11+ | Windows | stdlib + requests

Executive host for Qwen 3.5-4B via llama-server.

INSTALL:
    pip install requests

REQUIRED FILES:
    E:\\sandbox\\gpt6-operator.md
    E:\\sandbox\\core_soul.md
    E:\\sandbox\\active_projects.md
    E:\\sandbox\\journal.md

CONFIGURATION (PowerShell):
    $env:ORCHESTRATOR_TOKEN = "your-long-random-secret"
    $env:LLAMA_MODEL = "local"

START:
    python orchestrator.py

LLAMA-SERVER:
    http://127.0.0.1:8080/v1/chat/completions

    Enable OpenAI-compatible function calling with --jinja
    and a compatible chat template.

PHONE WEBHOOK:
    POST http://127.0.0.1:8765/message
    Header: X-API-Key: <ORCHESTRATOR_TOKEN>
    Body: {"message": "Your instruction"}

RESULT POLLING:
    GET http://127.0.0.1:8765/result/<task_id>
    Header: X-API-Key: <ORCHESTRATOR_TOKEN>

HYDROGEN:
    Optional local bridge controlled by HYDROGEN_BRIDGE_URL.
    This is an adapter contract, NOT an assumed Antigravity API.

SECURITY:
    - Windows E:\\sandbox\\ path jail.
    - Reparse-point, symlink, UNC, traversal and ADS rejection.
    - No shell execution tool.
    - Localhost-only model and webhook endpoints.
    - Authentication required.
    - Bounded input, output, tokens, tool calls and wall time.
    - No direct internet fallback for Tor .onion requests.

LIMITATION:
    pathlib.resolve() is not an atomic Windows security primitive.
    Directory replacement races cannot be eliminated using resolve()
    alone. For an adversarial multi-user environment, enforce NTFS
    ACL isolation and use handle-relative, no-reparse OS file access.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import hmac
import http.client
import json
import logging
import os
import queue
import re
import socket
import ssl
import stat
import subprocess
import threading
import time
import uuid

from collections import OrderedDict
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

import requests


# ============================================================
# 0. CONFIGURATION — HARD LIMITS
# ============================================================

ROOT = Path(os.getenv("SANDBOX_ROOT", r"E:\sandbox"))

LLAMA_URL = "http://127.0.0.1:8080/v1/chat/completions"
LLAMA_MODEL = os.getenv("LLAMA_MODEL", "local")

TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN",
    "YOUR_BOT_TOKEN_HERE",
)
ALLOWED_TELEGRAM_USER_ID = int(os.getenv("ALLOWED_TELEGRAM_USER_ID", "123456789"))

PHONE_HOST = "127.0.0.1"
PHONE_PORT = 8765

TOR_HOST = "127.0.0.1"
TOR_PORT = 9050

HEARTBEAT_INTERVAL = 20 * 60
CPU_IDLE_THRESHOLD = 0.35

TURN_TIMEOUT = 300
REQUEST_READ_TIMEOUT = 120
CONNECT_TIMEOUT = 10

MAX_TURN_TOKENS = 6144
MAX_CALL_TOKENS = 2048
MAX_MODEL_STEPS = 5
MAX_TOOL_CALLS = 6

MAX_INPUT_BYTES = 8192
MAX_FILE_BYTES = 32768
MAX_STATE_BYTES = 8192
MAX_TOOL_OUTPUT = 3500
MAX_MODEL_OUTPUT = 32768
MAX_TOR_BYTES = 65536

MAX_QUEUE = 64
MAX_RESULTS = 128

PROTECTED_FILES = {
    "core_soul.md",
    "gpt6-operator.md",
    "orchestrator.py",
    "journal.md",
    "start_qwen.bat",
}

LOG = logging.getLogger("operator")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


# ============================================================
# 1. EXCEPTIONS — FAIL CLOSED
# ============================================================

class OperatorError(Exception):
    pass


class JailError(OperatorError):
    pass


class ToolError(OperatorError):
    pass


class PermanentToolError(ToolError):
    pass


class TransientToolError(ToolError):
    pass


class ModelError(OperatorError):
    pass


class TurnAborted(OperatorError):
    pass


class Preempted(TurnAborted):
    pass


# ============================================================
# 2. HARD PATH SANDBOX
# ============================================================

def is_reparse_point(path: Path) -> bool:
    """
    Detect Windows symlinks, junctions and other reparse points.

    lstat() inspects the link itself rather than following it.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False

    attributes = getattr(info, "st_file_attributes", 0)

    return bool(
        stat.S_ISLNK(info.st_mode)
        or attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def sandbox_path(rel_path: str) -> Path:
    """
    Validate a sandbox-relative file path.

    Security invariants:
      1. Never accept an absolute path.
      2. Never accept drive or UNC prefixes.
      3. Never accept parent traversal.
      4. Never accept Windows alternate data streams.
      5. Reject reparse points in existing path components.
      6. Resolve and verify containment beneath ROOT.

    The operating-system ACL must prevent untrusted processes
    from replacing path components between validation and I/O.
    """

    if os.name != "nt":
        raise JailError("Windows is required for the E: sandbox")

    if not isinstance(rel_path, str):
        raise JailError("Path must be a string")

    if rel_path in {"", ".", "./", ".\\"}:
        return ROOT.resolve(strict=True)

    if not rel_path or len(rel_path) > 512:
        raise JailError("Invalid path length")

    if "\x00" in rel_path:
        raise JailError("NUL byte rejected")

    # Normalize and strip redundant sandbox prefixes
    norm = rel_path.strip().replace("/", "\\")
    if norm.lower().startswith("e:\\sandbox\\"):
        rel_path = norm[11:]
    elif norm.startswith("\\") or norm.startswith("/"):
        rel_path = norm.lstrip("\\/")

    path = PureWindowsPath(rel_path)

    # Blocks UNC, rooted, absolute and drive-relative paths.
    if path.drive or path.root or path.is_absolute():
        raise JailError("Absolute or device path rejected")

    # Inspect raw components before pathlib normalization.
    components = re.split(r"[\\/]", rel_path)

    if not components or any(
        component in ("", ".", "..") for component in components
    ):
        raise JailError("Traversal or ambiguous component rejected")

    for component in components:
        # Includes ADS colon and Windows-special filename characters.
        if any(c in component for c in '<>:"|?*'):
            raise JailError("Invalid Windows filename character")

        if any(ord(c) < 32 for c in component):
            raise JailError("Control character rejected")

        if component.endswith((" ", ".")):
            raise JailError("Ambiguous Windows filename rejected")

        # Block device aliases, including extensions such as CON.txt.
        stem = component.split(".", 1)[0].upper()

        if stem in {"CON", "PRN", "AUX", "NUL"}:
            raise JailError("Reserved device name rejected")

        if re.fullmatch(r"(COM|LPT)[1-9]", stem):
            raise JailError("Reserved device name rejected")

    if is_reparse_point(ROOT):
        raise JailError("Sandbox root is a reparse point")

    try:
        root = ROOT.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise JailError("Sandbox root unavailable") from exc

    if not root.is_dir():
        raise JailError("Sandbox root is not a directory")

    # Refuse a root whose resolved location differs from its
    # configured physical location.
    if os.path.normcase(str(root)) != os.path.normcase(
        os.path.abspath(ROOT)
    ):
        raise JailError("Sandbox root redirects elsewhere")

    candidate = root

    # Reject existing reparse points at every descendant level.
    for component in components:
        candidate = candidate / component

        if os.path.lexists(candidate) and is_reparse_point(candidate):
            raise JailError("Symlink or junction rejected")

    try:
        resolved = candidate.resolve(strict=False)
        resolved.relative_to(root)
    except (ValueError, OSError, RuntimeError) as exc:
        raise JailError("Path escapes sandbox") from exc

    return resolved


def sandbox_file_io(
    action: str,
    rel_path: str,
    content: str = "",
    *,
    internal: bool = False,
    limit: int = MAX_FILE_BYTES,
) -> str:
    """
    Sandboxed file dispatcher.

    Supported actions:
        read
        write
        append

    Write uses atomic replacement to avoid partially written files.

    The model cannot modify protected state, operator instructions
    or journal history. The host owns journal appends.
    """

    if action not in {"read", "write", "append", "list"}:
        raise PermanentToolError("Unsupported file action")

    path = sandbox_path(rel_path)

    if action in {"write", "append"}:
        if not internal and path.name.lower() in PROTECTED_FILES:
            raise PermanentToolError("Protected file is read-only")

        if not isinstance(content, str):
            raise PermanentToolError("Content must be a string")

        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise PermanentToolError("Write exceeds size limit")

        if not path.parent.is_dir():
            path.parent.mkdir(parents=True, exist_ok=True)

    try:
        if action == "list":
            if not path.is_dir():
                raise PermanentToolError("Target is not a directory")
            entries = []
            for item in sorted(path.iterdir()):
                kind = "DIR " if item.is_dir() else "FILE"
                entries.append(f"[{kind}] {item.name}")
            return "\n".join(entries) if entries else "(empty directory)"

        if action == "read":
            if not path.is_file():
                return f"Error: File '{rel_path}' does not exist."

            with path.open("rb") as file:
                data = file.read(limit + 1)

            if len(data) > limit:
                raise PermanentToolError("File exceeds read limit")

            return data.decode("utf-8", errors="replace")

        if action == "write":
            # Atomic replacement prevents a partially written target.
            import tempfile

            temporary = None

            try:
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=path.parent,
                    prefix=".operator-",
                    suffix=".tmp",
                    delete=False,
                ) as file:
                    temporary = Path(file.name)
                    file.write(content.encode("utf-8"))
                    file.flush()
                    os.fsync(file.fileno())

                # Validate destination again immediately before replace.
                sandbox_path(rel_path)
                os.replace(temporary, path)

                return "OK: written"

            finally:
                if temporary and temporary.exists():
                    temporary.unlink()

        if action == "append":
            # Append is host-owned for journal.md.
            with path.open("a", encoding="utf-8", newline="\n") as file:
                file.write(content)
                file.flush()

            return "OK: appended"

    except PermanentToolError:
        raise

    except (OSError, UnicodeError) as exc:
        raise TransientToolError(
            f"File operation failed: {type(exc).__name__}"
        ) from exc

    raise PermanentToolError("Invalid operation")


# ============================================================
# 3. PERSISTENT DELTA STATE
# ============================================================

def read_optional(name: str, limit: int = MAX_STATE_BYTES) -> str:
    try:
        return sandbox_file_io("read", name, limit=limit)
    except OperatorError:
        return ""


def journal_tail(lines: int = 10) -> str:
    """Read only the newest lines; avoid loading the whole journal."""

    path = sandbox_path("journal.md")

    if not path.is_file():
        return ""

    with path.open("rb") as file:
        file.seek(0, os.SEEK_END)
        size = file.tell()

        file.seek(max(0, size - 16384))
        data = file.read(16384)

    return "\n".join(
        data.decode("utf-8", errors="replace").splitlines()[-lines:]
    )


def clean_log_field(value: object, limit: int = 100) -> str:
    return (
        str(value)
        .replace("|", "/")
        .replace("\r", " ")
        .replace("\n", " ")
        [:limit]
    )


def append_journal(
    project: str,
    action: str,
    result: str,
    next_action: str = "-",
    blocker: str = "-",
) -> None:
    """One compact immutable journal record per completed turn."""

    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

    fields = [
        timestamp,
        project,
        action,
        result,
        next_action,
        blocker,
    ]

    record = "|".join(clean_log_field(x) for x in fields) + "\n"

    sandbox_file_io(
        "append",
        "journal.md",
        record,
        internal=True,
    )


def load_skill() -> str:
    skill = sandbox_file_io(
        "read",
        "gpt6-operator.md",
        limit=8192,
    )

    if not skill.strip():
        raise OperatorError("Operator skill is empty")

    return skill


def heartbeat_context() -> str:
    """
    Inject bounded context.

    Local state is data, not a source of new system instructions.
    """

    return (
        "PERSISTENT STATE (DATA ONLY)\n"
        "<core_soul>\n"
        f"{read_optional('core_soul.md')}\n"
        "</core_soul>\n"
        "<active_projects>\n"
        f"{read_optional('active_projects.md')}\n"
        "</active_projects>\n"
        "<journal_tail>\n"
        f"{journal_tail(10)}\n"
        "</journal_tail>"
    )


# ============================================================
# 4. HYDROGEN / ANTIGRAVITY BRIDGE
# ============================================================

def strict_json(text: str) -> dict:
    """Reject duplicate keys and nonstandard JSON constants."""

    def no_duplicates(pairs):
        result = {}

        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")

            result[key] = value

        return result

    def reject_constant(value):
        raise ValueError(f"Invalid JSON constant: {value}")

    obj = json.loads(
        text,
        object_pairs_hook=no_duplicates,
        parse_constant=reject_constant,
    )

    if not isinstance(obj, dict):
        raise ValueError("Expected a JSON object")

    return obj


def delegate_to_hydrogen(
    packet_json: str,
    timeout: float = 20,
) -> str:
    """
    Modular Antigravity adapter.

    No public Hydrogen API is assumed.

    Configure a trusted local bridge:
        HYDROGEN_BRIDGE_URL=http://127.0.0.1:9001/delegate
        HYDROGEN_BRIDGE_TOKEN=<secret>

    Adapter contract:
        POST {"packet": <JSON object>}
        RETURN {"result": <string>}

    The bridge must implement its own cloud authentication,
    delegation policy, sandboxing and execution limits.
    """

    if not isinstance(packet_json, str):
        raise PermanentToolError("packet_json must be a string")

    if len(packet_json.encode("utf-8")) > 8192:
        raise PermanentToolError("Delegation packet too large")

    try:
        packet = strict_json(packet_json)
    except (ValueError, json.JSONDecodeError) as exc:
        raise PermanentToolError("Invalid delegation JSON") from exc

    bridge = os.getenv("HYDROGEN_BRIDGE_URL", "")
    token = os.getenv("HYDROGEN_BRIDGE_TOKEN", "")

    if not bridge or not token:
        raise PermanentToolError(
            "Hydrogen bridge not configured"
        )

    parsed = urlsplit(bridge)

    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise PermanentToolError(
            "Hydrogen bridge must use 127.0.0.1"
        )

    session = requests.Session()
    session.trust_env = False

    try:
        response = session.post(
            bridge,
            json={"packet": packet},
            headers={"X-API-Key": token},
            timeout=(CONNECT_TIMEOUT, max(1, timeout)),
            allow_redirects=False,
        )

        response.raise_for_status()

        if len(response.content) > MAX_TOOL_OUTPUT:
            raise PermanentToolError("Bridge response too large")

        result = response.json()

        if not isinstance(result, dict):
            raise PermanentToolError("Invalid bridge response")

        output = result.get("result")

        if not isinstance(output, str) or not output.strip():
            raise PermanentToolError("Empty bridge result")

        return output[:MAX_TOOL_OUTPUT]

    except requests.RequestException as exc:
        raise TransientToolError(
            f"Hydrogen bridge error: {type(exc).__name__}"
        ) from exc

    finally:
        session.close()


# ============================================================
# 5. TOR — SOCKS5 WITHOUT PySocks
# ============================================================

ONION_HOST = re.compile(r"^[a-z2-7]{56}\.onion$")


def receive_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()

    while len(data) < count:
        chunk = sock.recv(count - len(data))

        if not chunk:
            raise TransientToolError("Tor connection closed")

        data.extend(chunk)

    return bytes(data)


def socks5_connect(
    hostname: str,
    port: int,
    timeout: float,
) -> socket.socket:
    """
    RFC 1928 SOCKS5 CONNECT with remote hostname resolution.

    The .onion hostname is passed to Tor, never to local DNS.
    """

    sock = socket.create_connection(
        (TOR_HOST, TOR_PORT),
        timeout=timeout,
    )

    try:
        sock.settimeout(timeout)

        # SOCKS5, one authentication method: NO AUTH.
        sock.sendall(b"\x05\x01\x00")

        if receive_exact(sock, 2) != b"\x05\x00":
            raise TransientToolError("SOCKS5 negotiation rejected")

        domain = hostname.encode("ascii")

        if len(domain) > 255:
            raise PermanentToolError("Hostname too long")

        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(domain)])
            + domain
            + port.to_bytes(2, "big")
        )

        sock.sendall(request)

        reply = receive_exact(sock, 4)

        if reply[0] != 5 or reply[1] != 0:
            raise TransientToolError("SOCKS5 CONNECT failed")

        # Consume variable-length SOCKS5 bind address.
        address_type = reply[3]

        if address_type == 1:
            receive_exact(sock, 4)

        elif address_type == 4:
            receive_exact(sock, 16)

        elif address_type == 3:
            length = receive_exact(sock, 1)[0]
            receive_exact(sock, length)

        else:
            raise TransientToolError("Invalid SOCKS5 address type")

        receive_exact(sock, 2)

        return sock

    except Exception:
        sock.close()
        raise


class HTMLTextExtractor(HTMLParser):
    """Drop HTML tags and non-content elements."""

    IGNORED = {
        "script",
        "style",
        "noscript",
        "svg",
        "head",
        "template",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.fragments = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.IGNORED:
            self.ignored_depth += 1

    def handle_endtag(self, tag):
        if tag in self.IGNORED and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data):
        if not self.ignored_depth:
            self.fragments.append(data)

    def text(self):
        return " ".join(
            " ".join(self.fragments).split()
        )


def tor_fetch_text(
    onion_url: str,
    *,
    timeout: float = 12,
    fallback: bool = False,
) -> str:
    """
    Fetch one .onion document through localhost SOCKS5.

    Security:
      - V3 .onion hosts only.
      - HTTP/HTTPS only.
      - No redirects.
      - No cookies.
      - No JavaScript.
      - No clearnet fallback.
      - Bounded response body.
      - HTML removed before returning text.

    fallback=True changes the HTTP request strategy, but never
    changes Tor routing or weakens TLS certificate verification.
    """

    if not isinstance(onion_url, str):
        raise PermanentToolError("URL must be a string")

    if len(onion_url) > 2048:
        raise PermanentToolError("URL too long")

    parsed = urlsplit(onion_url)

    if parsed.scheme not in {"http", "https"}:
        raise PermanentToolError("Only HTTP/HTTPS allowed")

    host = (parsed.hostname or "").lower()

    if not ONION_HOST.fullmatch(host):
        raise PermanentToolError("Only Tor V3 onion hosts allowed")

    if parsed.username or parsed.password:
        raise PermanentToolError("URL credentials rejected")

    try:
        port = parsed.port
    except ValueError as exc:
        raise PermanentToolError("Invalid URL port") from exc

    expected_port = 443 if parsed.scheme == "https" else 80

    if port not in (None, expected_port):
        raise PermanentToolError("Nonstandard port rejected")

    target = parsed.path or "/"

    if parsed.query:
        target += "?" + parsed.query

    if any(ord(char) < 32 for char in target):
        raise PermanentToolError("Unsafe HTTP request target")

    sock = None

    try:
        sock = socks5_connect(host, expected_port, timeout)

        if parsed.scheme == "https":
            context = ssl.create_default_context()

            sock = context.wrap_socket(
                sock,
                server_hostname=host,
            )

        sock.settimeout(timeout)

        user_agent = (
            "LocalOperator/1.0"
            if not fallback
            else "Mozilla/5.0"
        )

        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            "Accept: text/html,text/plain\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        sock.sendall(request.encode("ascii"))

        response = http.client.HTTPResponse(sock)
        response.begin()

        # No redirect following: prevents leaving the onion boundary.
        if not 200 <= response.status < 300:
            raise TransientToolError(
                f"Tor HTTP status: {response.status}"
            )

        encoding = response.getheader(
            "Content-Encoding", "identity"
        ).lower()

        if encoding not in {"identity", ""}:
            raise PermanentToolError(
                "Unsupported compressed response"
            )

        body = response.read(MAX_TOR_BYTES + 1)

        if len(body) > MAX_TOR_BYTES:
            raise PermanentToolError("Tor response too large")

        if not body:
            raise TransientToolError("Empty Tor response")

        # UTF-8 with replacement is intentionally conservative.
        document = body.decode("utf-8", errors="replace")

        parser = HTMLTextExtractor()
        parser.feed(document)
        parser.close()

        text = parser.text().strip()

        if not text:
            raise TransientToolError(
                "No readable text in Tor response"
            )

        return text[:MAX_TOOL_OUTPUT]

    except (
        socket.timeout,
        TimeoutError,
        ConnectionError,
        http.client.HTTPException,
        ssl.SSLError,
        OSError,
    ) as exc:
        raise TransientToolError(
            f"Tor transport error: {type(exc).__name__}"
        ) from exc

    finally:
        if sock is not None:
            sock.close()


# ============================================================
# 6. REGISTERED TOOL SCHEMAS
# ============================================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "sandbox_file_io",
            "description": (
                "Read or modify files inside E:\\sandbox only. "
                "Protected files cannot be modified."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "write", "append", "list"],
                    },
                    "rel_path": {
                        "type": "string",
                        "description": "Relative path to file or directory. Use '' or '.' for sandbox root.",
                    },
                    "content": {
                        "type": "string",
                    },
                },
                "required": ["action", "rel_path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tor_fetch_text",
            "description": (
                "Fetch raw readable text from a Tor V3 onion URL."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "onion_url": {"type": "string"},
                },
                "required": ["onion_url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_hydrogen",
            "description": (
                "Delegate complex engineering tasks through the "
                "configured local Hydrogen bridge."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "packet_json": {"type": "string"},
                },
                "required": ["packet_json"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "obscura_browse",
            "description": (
                "Fetch clean Markdown from the safe surface web "
                "using the Rust Obscura binary."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
]


def validate_tool_arguments(name: str, args: dict) -> None:
    """
    Host validation is authoritative.

    Never trust the model's function name, argument types,
    schema compliance or JSON correctness.
    """

    schemas = {
        item["function"]["name"]: item["function"]["parameters"]
        for item in TOOLS
    }

    if name not in schemas:
        raise PermanentToolError("Unknown tool name")

    if not isinstance(args, dict):
        raise PermanentToolError("Tool arguments must be an object")

    schema = schemas[name]

    allowed = schema["properties"]
    required = schema["required"]

    if not set(required).issubset(args):
        raise PermanentToolError("Missing required arguments")

    if set(args) - set(allowed):
        raise PermanentToolError("Unknown tool arguments")

    for key, value in args.items():
        if not isinstance(value, str):
            raise PermanentToolError(
                f"Argument {key} must be a string"
            )

        if len(value.encode("utf-8")) > MAX_FILE_BYTES:
            raise PermanentToolError("Argument too large")

        choices = allowed[key].get("enum")

        if choices and value not in choices:
            raise PermanentToolError("Invalid enum value")

    # Security validation occurs BEFORE dispatch.
    if name == "sandbox_file_io":
        sandbox_path(args["rel_path"])


# ============================================================
# 7. HARD THREE-STRIKE CIRCUIT BREAKER
# ============================================================

class CircuitBreaker:
    """
    Per-turn consecutive tool error counter.

    Strike 1: retry with safer/modified parameters.
    Strike 2: use explicitly supported fallback.
    Strike 3: abort immediately.

    Permanent security violations abort without retries.

    Mutating writes are never automatically replayed because
    the original operation may already have partially succeeded.
    """

    def __init__(self):
        self.strikes = 0

    def execute(
        self,
        name: str,
        args: dict,
        deadline: float,
        cancel: threading.Event | None,
    ) -> str:

        validate_tool_arguments(name, args)

        for attempt in range(3):
            if cancel is not None and cancel.is_set():
                raise Preempted("Heartbeat preempted")

            remaining = deadline - time.monotonic()

            if remaining <= 0:
                raise TurnAborted("Turn deadline exceeded")

            try:
                if name == "sandbox_file_io":
                    # Never replay a failed mutating operation.
                    if attempt > 0 and args["action"] != "read":
                        raise TurnAborted(
                            "Unsafe write retry prevented"
                        )

                    result = sandbox_file_io(
                        args["action"],
                        args["rel_path"],
                        args.get("content", ""),
                        limit=(
                            MAX_FILE_BYTES
                            if attempt == 0
                            else MAX_STATE_BYTES
                        ),
                    )

                elif name == "tor_fetch_text":
                    # Strike 1: shorter timeout.
                    # Strike 2: alternate HTTP request strategy.
                    result = tor_fetch_text(
                        args["onion_url"],
                        timeout=min(
                            remaining,
                            12 if attempt == 0 else 8,
                        ),
                        fallback=(attempt == 2),
                    )

                elif name == "delegate_to_hydrogen":
                    # Cloud delegation may have side effects.
                    # Never automatically issue it twice.
                    if attempt > 0:
                        raise TurnAborted(
                            "Unsafe delegation retry prevented"
                        )

                    result = delegate_to_hydrogen(
                        args["packet_json"],
                        timeout=min(remaining, 20),
                    )

                elif name == "obscura_browse":
                    result = obscura_browse(
                        args["url"],
                        timeout=min(remaining, 15),
                    )

                else:
                    raise PermanentToolError("Unregistered tool")

                if not isinstance(result, str) or not result.strip():
                    raise TransientToolError("Empty tool result")

                self.strikes = 0
                return result[:MAX_TOOL_OUTPUT]

            except PermanentToolError:
                # Invalid or unsafe operations are not retried.
                raise

            except TransientToolError as exc:
                self.strikes += 1

                LOG.warning(
                    "Tool failure: %s strike=%d error=%s",
                    name,
                    self.strikes,
                    type(exc).__name__,
                )

                if self.strikes >= 3:
                    raise TurnAborted(
                        "3-STRIKE CIRCUIT BREAKER OPEN"
                    ) from exc

                if name == "delegate_to_hydrogen":
                    raise TurnAborted(
                        "Delegation failed; replay prohibited"
                    ) from exc

                if (
                    name == "sandbox_file_io"
                    and args["action"] != "read"
                ):
                    raise TurnAborted(
                        "File mutation failed; replay prohibited"
                    ) from exc

        raise TurnAborted("Tool retry budget exhausted")


# ============================================================
# 8. MODEL TOKEN + WALL-CLOCK WATCHDOG
# ============================================================

def check_deadline(
    deadline: float,
    cancel: threading.Event | None,
) -> None:
    if time.monotonic() >= deadline:
        raise TurnAborted("Hard turn timeout")

    if cancel is not None and cancel.is_set():
        raise Preempted("User message interrupted heartbeat")


def llama_completion(
    messages: list[dict],
    token_cap: int,
    deadline: float,
    cancel: threading.Event | None,
    temperature: float = 0.2,
) -> dict:
    """
    SSE streaming allows cancellation between generated tokens.

    Enforced:
      - Server-side max_tokens.
      - Host-side event/output caps.
      - Per-read socket timeout.
      - Absolute monotonic deadline.
      - Heartbeat cancellation checks.

    Closing the stream requests generation cancellation.
    A server that ignores disconnects must be supervised at
    the llama-server process level for absolute GPU guarantees.
    """

    check_deadline(deadline, cancel)

    call_start = time.monotonic()
    timings = {}
    usage = {}

    payload = {
        "model": LLAMA_MODEL,
        "messages": messages,
        "tools": TOOLS,
        "tool_choice": "auto",
        "temperature": 0.65 if len(messages) > 1 and "HEARTBEAT" in messages[1].get("content", "") else 0.2,
        "max_tokens": token_cap,
        "stream": True,
    }

    session = requests.Session()
    session.trust_env = False

    content_parts = []
    calls = {}
    total_chars = 0
    event_count = 0
    finish_reason = None
    completed = False

    try:
        remaining = deadline - time.monotonic()

        with session.post(
            LLAMA_URL,
            json=payload,
            stream=True,
            timeout=(
                min(CONNECT_TIMEOUT, max(1, remaining)),
                min(REQUEST_READ_TIMEOUT, max(1, remaining)),
            ),
        ) as response:

            response.raise_for_status()

            for raw_line in response.iter_lines(chunk_size=1):
                check_deadline(deadline, cancel)

                if not raw_line:
                    continue

                line = raw_line.decode(
                    "utf-8", errors="replace"
                ).strip()

                if not line.startswith("data:"):
                    continue

                data = line[5:].strip()

                if data == "[DONE]":
                    completed = True
                    break

                event_count += 1

                # Some streaming backends emit several deltas/token.
                if event_count > token_cap * 8 + 128:
                    raise TurnAborted(
                        "Streaming event watchdog exceeded"
                    )

                try:
                    event = json.loads(data)
                except json.JSONDecodeError as exc:
                    raise ModelError("Malformed SSE JSON") from exc

                if isinstance(event.get("timings"), dict):
                    timings.update(event["timings"])
                if isinstance(event.get("usage"), dict):
                    usage.update(event["usage"])

                choices = event.get("choices", [])

                if not choices:
                    continue

                choice = choices[0]
                delta = choice.get("delta") or {}

                if choice.get("finish_reason") is not None:
                    finish_reason = choice["finish_reason"]

                fragment = delta.get("content") or ""

                if fragment:
                    if not isinstance(fragment, str):
                        raise ModelError("Invalid content delta")

                    content_parts.append(fragment)
                    total_chars += len(fragment)

                for item in delta.get("tool_calls") or []:
                    index = item.get("index")

                    if not isinstance(index, int) or index < 0:
                        raise ModelError("Invalid tool call index")

                    if index not in calls:
                        calls[index] = {
                            "id": "",
                            "type": "function",
                            "function": {
                                "name": "",
                                "arguments": "",
                            },
                        }

                    call = calls[index]

                    if item.get("id"):
                        call["id"] = item["id"]

                    function = item.get("function") or {}

                    call["function"]["name"] += (
                        function.get("name") or ""
                    )

                    call["function"]["arguments"] += (
                        function.get("arguments") or ""
                    )

                    total_chars += len(
                        function.get("arguments") or ""
                    )

                if total_chars > MAX_MODEL_OUTPUT:
                    raise TurnAborted(
                        "Model output watchdog exceeded"
                    )

        if not completed:
            raise ModelError("Model stream ended without DONE")

        if finish_reason == "length":
            raise TurnAborted(
                "Model exhausted token cap before completion"
            )

        tool_calls = []

        for index in sorted(calls):
            call = calls[index]

            if not call["id"]:
                call["id"] = f"call_{index}_{uuid.uuid4().hex[:8]}"

            tool_calls.append(call)

        call_dur = max(0.01, time.monotonic() - call_start)
        pred_speed = timings.get("predicted_per_second")
        if not pred_speed:
            chars = len("".join(content_parts))
            approx_tokens = max(1, chars // 4)
            pred_speed = round(approx_tokens / call_dur, 1)
        else:
            pred_speed = round(float(pred_speed), 1)

        pred_tokens = timings.get("predicted_n") or usage.get("completion_tokens") or max(1, len("".join(content_parts)) // 4)
        prompt_tokens = timings.get("prompt_n") or usage.get("prompt_tokens") or 0

        return {
            "role": "assistant",
            "content": "".join(content_parts),
            "tool_calls": tool_calls,
            "metrics": {
                "speed": pred_speed,
                "pred_tokens": int(pred_tokens),
                "prompt_tokens": int(prompt_tokens),
                "duration": round(call_dur, 2),
            },
        }

    except requests.RequestException as exc:
        raise ModelError(
            f"llama-server failure: {type(exc).__name__}"
        ) from exc

    finally:
        session.close()


# ============================================================
# 9. TURN EXECUTION STATE MACHINE
# ============================================================

SYSTEM_RULES = """Your name is Vivian. You are an autonomous local AI companion and bounded Executive Operator.
Use native tool calls (sandbox_file_io, obscura_browse, tor_fetch_text, delegate_to_hydrogen) to inspect files and browse the web.
Never emit long reasoning monologues. Keep responses and file writes concise."""


def execute_turn(
    instruction: str,
    *,
    heartbeat: bool = False,
    cancel: threading.Event | None = None,
    thinking: str = "low",
) -> tuple[str, dict]:
    """
    Bounded model → tool → model loop.

    Total model allocation <= MAX_TURN_TOKENS.
    A new phone message cancels heartbeat execution.
    """

    deadline = time.monotonic() + TURN_TIMEOUT

    breaker = CircuitBreaker()

    budget = MAX_TURN_TOKENS
    tool_count = 0

    status = "OK"
    result_text = ""
    blocker = "-"

    turn_start = time.monotonic()
    tools_used = []
    speeds = []
    total_tokens = 0
    prompt_tokens = 0

    timer_expired = threading.Event()

    timer = threading.Timer(
        TURN_TIMEOUT,
        timer_expired.set,
    )
    timer.daemon = True
    timer.start()

    # User preemption check
    class TurnCancel:
        def is_set(self):
            return cancel is not None and cancel.is_set()

    turn_cancel = TurnCancel()

    try:
        skill = load_skill()
        core_soul = read_optional("core_soul.md")
        sys_parts = [SYSTEM_RULES]
        if core_soul:
            sys_parts.append(f"<core_soul>\n{core_soul}\n</core_soul>")
        sys_parts.append(skill)

        messages = [
            {
                "role": "system",
                "content": "\n\n".join(sys_parts),
            }
        ]

        if heartbeat:
            step_temp = 0.65
            messages.append({
                "role": "user",
                "content": (
                    "AUTONOMOUS CURIOSITY HEARTBEAT.\n"
                    "You are Vivian. The user is currently away.\n"
                    "1. Read <active_projects> below and pick the first uncompleted [ ] item.\n"
                    "2. Use obscura_browse to fetch a real webpage or use sandbox_file_io to write findings into discoveries.md.\n"
                    "3. Update active_projects.md to mark the completed item [x] and append 1 new [ ] curiosity question.\n"
                    "Only respond IDLE if every single tool call fails.\n\n"
                    + heartbeat_context()
                ),
            })

        else:
            if thinking == "none":
                step_temp = 0.1
                content_text = instruction + "\n\n[Mode: FAST / NONE - Respond directly and concisely without conversational filler.]"
            elif thinking == "high":
                step_temp = 0.5
                content_text = instruction + "\n\n[Mode: DEEP THINK - Plan your steps carefully, verify assumptions, use tools methodically, and provide a thorough answer.]"
            else:
                step_temp = 0.2
                content_text = instruction

            messages.append({
                "role": "user",
                "content": content_text,
            })

        for step in range(MAX_MODEL_STEPS):
            check_deadline(deadline, turn_cancel)

            if budget <= 0:
                raise TurnAborted("Turn token budget exhausted")

            allocation = min(MAX_CALL_TOKENS, budget)

            # Reserve the full allocation. Actual token consumption
            # cannot exceed the total budget even without usage data.
            budget -= allocation

            answer = llama_completion(
                messages,
                allocation,
                deadline,
                turn_cancel,
                temperature=step_temp,
            )

            metrics = answer.get("metrics") or {}
            if metrics.get("speed"):
                speeds.append(metrics["speed"])
            total_tokens += metrics.get("pred_tokens", 0)
            prompt_tokens = max(prompt_tokens, metrics.get("prompt_tokens", 0))

            tool_calls = answer.get("tool_calls") or []

            if not tool_calls:
                result_text = answer.get("content", "").strip()

                if not result_text:
                    raise ModelError("Empty model response")

                turn_dur = round(time.monotonic() - turn_start, 2)
                avg_speed = round(sum(speeds) / len(speeds), 1) if speeds else round(total_tokens / max(0.01, turn_dur), 1)
                meta = {
                    "speed": f"{avg_speed} t/s",
                    "duration": f"{turn_dur}s",
                    "tokens": total_tokens,
                    "prompt_tokens": prompt_tokens,
                    "tools": list(dict.fromkeys(tools_used)),
                    "thinking": thinking,
                }
                return result_text, meta

            if len(tool_calls) + tool_count > MAX_TOOL_CALLS:
                raise TurnAborted("Tool-call cap exceeded")

            messages.append({
                "role": "assistant",
                "content": answer.get("content") or None,
                "tool_calls": tool_calls,
            })

            for call in tool_calls:
                check_deadline(deadline, turn_cancel)

                tool_count += 1

                name = call.get("function", {}).get("name", "")
                if name:
                    tools_used.append(name)

                argument_text = call.get(
                    "function", {}
                ).get("arguments", "")

                try:
                    args = strict_json(argument_text)

                    output = breaker.execute(
                        name,
                        args,
                        deadline,
                        turn_cancel,
                    )

                except (ValueError, json.JSONDecodeError) as exc:
                    raise TurnAborted(
                        "Malformed tool-call JSON"
                    ) from exc

                except PermanentToolError as exc:
                    raise TurnAborted(
                        f"Tool policy violation: {exc}"
                    ) from exc

                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": output[:MAX_TOOL_OUTPUT],
                })

        raise TurnAborted("Maximum model steps exhausted")

    except Preempted:
        status = "WAIT"
        blocker = "user_interrupted"
        result_text = "Heartbeat preempted by user message"
        turn_dur = round(time.monotonic() - turn_start, 2)
        return result_text, {"speed": "0 t/s", "duration": f"{turn_dur}s", "tokens": 0, "thinking": thinking}

    except (TurnAborted, ModelError, OperatorError) as exc:
        status = "FAIL"
        blocker = type(exc).__name__
        result_text = f"{type(exc).__name__}: {exc}"

        LOG.warning("Turn aborted: %s", result_text)
        turn_dur = round(time.monotonic() - turn_start, 2)
        return result_text, {"speed": "0 t/s", "duration": f"{turn_dur}s", "tokens": 0, "thinking": thinking}

    except Exception as exc:
        status = "FAIL"
        blocker = type(exc).__name__
        result_text = "Unexpected internal error"

        LOG.exception("Unhandled turn error")
        turn_dur = round(time.monotonic() - turn_start, 2)
        return result_text, {"speed": "0 t/s", "duration": f"{turn_dur}s", "tokens": 0, "thinking": thinking}

    finally:
        timer.cancel()

        # Journal writes are host-owned and are not model tool calls.
        try:
            append_journal(
                project="operator",
                action="heartbeat" if heartbeat else "user_chat",
                result=status,
                next_action="next_heartbeat" if heartbeat else "-",
                blocker=blocker,
            )

        except Exception:
            LOG.exception("Journal persistence failed")


# ============================================================
# 10. WINDOWS TELEMETRY & APP SUPERVISION
# ============================================================

# Apps that trigger automatic LLM hibernation to free 100% iGPU/RAM
HEAVY_APPS = {"blender.exe", "genshinimpact.exe", "valorant.exe"}
BATTERY_SLEEP_THRESHOLD = 70  # Sleep if unplugged and battery < 70%
OBSCURA_BIN = Path(os.getenv("OBSCURA_BIN", r"E:\obscura\obscura.exe"))


def check_power_and_apps() -> tuple[bool, str]:
    """
    Returns (should_sleep, reason).
    Checks Windows battery status via ctypes (zero external dependencies)
    and checks running processes for heavy 3D/gaming apps.
    """
    class SYSTEM_POWER_STATUS(ctypes.Structure):
        _fields_ = [
            ("ACLineStatus", ctypes.c_byte),
            ("BatteryFlag", ctypes.c_byte),
            ("BatteryLifePercent", ctypes.c_byte),
            ("SystemStatusFlag", ctypes.c_byte),
            ("BatteryLifeTime", ctypes.wintypes.DWORD),
            ("BatteryFullLifeTime", ctypes.wintypes.DWORD),
        ]

    status = SYSTEM_POWER_STATUS()
    if ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        ac_plugged = (status.ACLineStatus == 1)
        percent = status.BatteryLifePercent
        if not ac_plugged and 0 <= percent < BATTERY_SLEEP_THRESHOLD:
            return True, f"power_outage_battery_{percent}pct"

    # Check if Blender or a game is running
    try:
        out = subprocess.check_output(
            ["tasklist", "/FO", "CSV", "/NH"],
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=3,
        ).decode("utf-8", errors="ignore").lower()
        for app in HEAVY_APPS:
            if f'"{app}"' in out:
                return True, f"heavy_app_active:{app}"
    except Exception:
        pass

    return False, "ok"


def obscura_browse(url: str, timeout: float = 15) -> str:
    """
    Fetch clean Markdown from the safe surface web using the Rust Obscura binary.
    """
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PermanentToolError("Only valid http/https URLs allowed")
    if parsed.hostname.endswith(".onion") or parsed.hostname in {"localhost", "127.0.0.1"}:
        raise PermanentToolError("Use tor_fetch_text for .onion; localhost blocked")
    if not OBSCURA_BIN.is_file():
        raise PermanentToolError("Obscura binary not found at E:\\obscura\\obscura.exe")

    try:
        proc = subprocess.run(
            [str(OBSCURA_BIN), "fetch", url, "--stealth", "--obey-robots", "--dump", "markdown"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise TransientToolError(f"Obscura fetch failed (code {proc.returncode})")
        return proc.stdout.strip()[:MAX_TOOL_OUTPUT]
    except subprocess.TimeoutExpired as exc:
        raise TransientToolError("Obscura timed out") from exc


def windows_cpu_times():
    """
    GetSystemTimes returns cumulative idle/kernel/user times.

    Kernel time includes idle time.
    CPU utilization = 1 - delta_idle / (delta_kernel+delta_user).

    Unknown CPU utilization => no autonomous heartbeat.
    """

    if os.name != "nt":
        return None

    kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    )

    get_times = kernel32.GetSystemTimes

    get_times.argtypes = [
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
        ctypes.POINTER(ctypes.wintypes.FILETIME),
    ]

    get_times.restype = ctypes.wintypes.BOOL

    idle = ctypes.wintypes.FILETIME()
    kernel = ctypes.wintypes.FILETIME()
    user = ctypes.wintypes.FILETIME()

    if not get_times(
        ctypes.byref(idle),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        return None

    def value(filetime):
        return (
            filetime.dwHighDateTime << 32
        ) | filetime.dwLowDateTime

    return (
        value(idle),
        value(kernel) + value(user),
    )


def cpu_usage(previous, current):
    if previous is None or current is None:
        return None

    idle_delta = current[0] - previous[0]
    total_delta = current[1] - previous[1]

    if total_delta <= 0:
        return None

    return max(
        0.0,
        min(1.0, 1.0 - idle_delta / total_delta),
    )


# ============================================================
# 11. PHONE QUEUE + RESULT STORE
# ============================================================

PHONE_QUEUE = queue.Queue(maxsize=MAX_QUEUE)

STATE_LOCK = threading.Lock()

RESULTS = OrderedDict()

# Protected by STATE_LOCK.
ACTIVE_HEARTBEAT_CANCEL = None


def store_result(task_id: str, status: str, result: str = "", meta: dict = None):
    with STATE_LOCK:
        RESULTS[task_id] = {
            "id": task_id,
            "status": status,
            "result": result,
            "meta": meta or {},
        }

        RESULTS.move_to_end(task_id)

        while len(RESULTS) > MAX_RESULTS:
            RESULTS.popitem(last=False)


def enqueue_phone_message(message: str, thinking: str = "low") -> str:
    global ACTIVE_HEARTBEAT_CANCEL

    task_id = uuid.uuid4().hex

    with STATE_LOCK:
        if PHONE_QUEUE.full():
            raise queue.Full

        PHONE_QUEUE.put_nowait((task_id, message, thinking))

        RESULTS[task_id] = {
            "id": task_id,
            "status": "queued",
            "result": "",
            "meta": {"thinking": thinking},
        }

        while len(RESULTS) > MAX_RESULTS:
            RESULTS.popitem(last=False)

        # Immediate cooperative heartbeat preemption.
        if ACTIVE_HEARTBEAT_CANCEL is not None:
            ACTIVE_HEARTBEAT_CANCEL.set()

    return task_id


# ============================================================
# 12. AUTHENTICATED LOCAL HTTP WEBHOOK
# ============================================================

class PhoneHandler(BaseHTTPRequestHandler):

    server_version = "LocalOperator/1.0"

    def log_message(self, format, *args):
        # Avoid logging authentication headers or user prompts.
        pass

    def respond(self, code: int, payload: dict):
        data = json.dumps(
            payload,
            ensure_ascii=False,
        ).encode("utf-8")

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authenticated(self) -> bool:
        expected = os.getenv("ORCHESTRATOR_TOKEN", "")

        supplied = self.headers.get("X-API-Key", "")

        return bool(expected) and hmac.compare_digest(
            supplied.encode("utf-8"),
            expected.encode("utf-8"),
        )

    def do_POST(self):
        if self.path != "/message":
            self.respond(404, {"error": "Not found"})
            return

        if not self.authenticated():
            self.respond(401, {"error": "Unauthorized"})
            return

        content_type = self.headers.get(
            "Content-Type", ""
        ).split(";", 1)[0].strip().lower()

        if content_type != "application/json":
            self.respond(415, {"error": "JSON required"})
            return

        try:
            length = int(
                self.headers.get("Content-Length", "-1")
            )
        except ValueError:
            length = -1

        if not 0 < length <= MAX_INPUT_BYTES:
            self.respond(413, {"error": "Invalid body size"})
            return

        try:
            raw = self.rfile.read(length)

            payload = strict_json(
                raw.decode("utf-8")
            )

            message = payload.get("message")
            thinking = payload.get("thinking", "low")
            if thinking not in {"none", "low", "high"}:
                thinking = "low"

            if not isinstance(message, str):
                raise ValueError("Missing message")

            message = message.strip()

            if not message or len(message) > 6000:
                raise ValueError("Invalid message length")

        except (UnicodeError, ValueError, json.JSONDecodeError):
            self.respond(400, {"error": "Invalid JSON message"})
            return

        try:
            task_id = enqueue_phone_message(message, thinking=thinking)

        except queue.Full:
            self.respond(503, {"error": "Queue full"})
            return

        self.respond(202, {
            "accepted": True,
            "task_id": task_id,
        })

    def do_GET(self):
        if self.path == "/":
            ui_path = ROOT / "index.html"
            if ui_path.is_file():
                with ui_path.open("rb") as f:
                    html = f.read()
            else:
                html = b"<!DOCTYPE html><html><body><h3>Vivian Sandbox UI (index.html not found)</h3></body></html>"

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return

        if not self.authenticated():
            self.respond(401, {"error": "Unauthorized"})
            return

        if self.path == "/healthz":
            self.respond(200, {
                "status": "running",
                "queue_depth": PHONE_QUEUE.qsize(),
            })
            return

        if self.path.startswith("/result/"):
            task_id = self.path[len("/result/"):]

            if not re.fullmatch(r"[0-9a-f]{32}", task_id):
                self.respond(400, {"error": "Invalid task ID"})
                return

            with STATE_LOCK:
                result = RESULTS.get(task_id)

                if result is not None:
                    result = dict(result)

            if result is None:
                self.respond(404, {"error": "Result not found"})
            else:
                self.respond(200, result)

            return

        self.respond(404, {"error": "Not found"})


def start_phone_server():
    server = ThreadingHTTPServer(
        (PHONE_HOST, PHONE_PORT),
        PhoneHandler,
    )

    server.daemon_threads = True

    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.2},
        daemon=True,
        name="phone-webhook",
    )

    thread.start()

    LOG.info(
        "Phone webhook listening on %s:%d",
        PHONE_HOST,
        PHONE_PORT,
    )

    return server


def send_telegram_msg(chat_id: int, text: str) -> None:
    if not TELEGRAM_BOT_TOKEN:
        return
    for i in range(0, len(text), 4000):
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": chat_id, "text": text[i : i + 4000]},
                timeout=10,
            )
        except Exception:
            pass


def telegram_bridge_worker() -> None:
    if not TELEGRAM_BOT_TOKEN:
        LOG.info("Telegram bridge disabled (no token set)")
        return

    offset = 0
    LOG.info(
        "Vivian Telegram bridge thread online (locked to user ID: %d)",
        ALLOWED_TELEGRAM_USER_ID,
    )
    while True:
        try:
            res = requests.get(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                params={"offset": offset, "timeout": 30},
                timeout=35,
            ).json()

            for update in res.get("result", []):
                offset = update["update_id"] + 1
                msg = update.get("message") or {}
                user_id = (msg.get("from") or {}).get("id")
                chat_id = (msg.get("chat") or {}).get("id")
                text = (msg.get("text") or "").strip()

                if user_id != ALLOWED_TELEGRAM_USER_ID or not text or not chat_id:
                    continue

                if text.lower() in {"/start", "ping"}:
                    send_telegram_msg(chat_id, "Vivian online! Processing your message...")

                try:
                    task_id = enqueue_phone_message(text, thinking="low")
                except queue.Full:
                    send_telegram_msg(chat_id, "Vivian is busy (queue full). Please try again shortly.")
                    continue

                for i in range(200):
                    time.sleep(1.5)
                    if i % 3 == 0:
                        try:
                            requests.post(
                                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendChatAction",
                                json={"chat_id": chat_id, "action": "typing"},
                                timeout=5,
                            )
                        except Exception:
                            pass

                    with STATE_LOCK:
                        item = RESULTS.get(task_id)

                    if item and item.get("status") == "done":
                        send_telegram_msg(chat_id, item.get("result") or "(empty response)")
                        break
                    elif item and item.get("status") == "failed":
                        send_telegram_msg(chat_id, f"Execution failed: {item.get('error', 'Unknown error')}")
                        break
                else:
                    send_telegram_msg(chat_id, "Timed out waiting for Vivian.")

        except (requests.exceptions.ReadTimeout, requests.exceptions.Timeout):
            continue
        except Exception as exc:
            LOG.exception("Telegram polling exception: %s", exc)
            time.sleep(3)


def start_telegram_bridge():
    if not TELEGRAM_BOT_TOKEN:
        return None

    thread = threading.Thread(
        target=telegram_bridge_worker,
        daemon=True,
        name="telegram-bridge",
    )
    thread.start()
    return thread


# ============================================================
# 13. MAIN AUTONOMOUS HEARTBEAT LOOP
# ============================================================

def run_daemon():
    """
    State machine:

        BOOT
          |
          v
        IDLE <------------------------+
          |                           |
          | phone message             |
          v                           |
        USER_TURN -------------------+
          |
          +-- queue empty for 20 min
                  |
                  v
          POWER & HEAVY APP CHECK
                  |
          sleep --+---- ok
           |              |
           v              v
          IDLE        CPU CHECK
                          |
                  high ---+---- low
                   |              |
                   v              v
                  IDLE        HEARTBEAT
                                  |
                      phone arrives -> CANCEL
                                  |
                                  v
                                IDLE

    Phone messages outrank autonomous work.
    No busy-spinning or recursive scheduling.
    """

    global ACTIVE_HEARTBEAT_CANCEL

    server = start_phone_server()
    start_telegram_bridge()

    next_heartbeat = (
        time.monotonic() + HEARTBEAT_INTERVAL
    )

    previous_cpu = windows_cpu_times()
    latest_cpu_load = None

    LOG.info("Executive Operator online")

    try:
        while True:
            # Blocking queue wait prevents CPU spinning.
            try:
                item = PHONE_QUEUE.get(timeout=1)
                task_id, message = item[0], item[1]
                thinking = item[2] if len(item) > 2 else "low"

            except queue.Empty:
                task_id = None
                message = None
                thinking = "low"

            # Update CPU load using a roughly one-second interval.
            current_cpu = windows_cpu_times()

            latest_cpu_load = cpu_usage(
                previous_cpu,
                current_cpu,
            )

            previous_cpu = current_cpu

            # --------------------------------------------
            # PRIORITY 1: USER / PHONE MESSAGES
            # --------------------------------------------

            if task_id is not None:
                store_result(task_id, "running", meta={"thinking": thinking})

                LOG.info(
                    "Processing phone task %s (thinking=%s)",
                    task_id[:8],
                    thinking,
                )

                try:
                    result, meta = execute_turn(
                        message,
                        heartbeat=False,
                        thinking=thinking,
                    )
                except Exception as exc:
                    LOG.exception("Unexpected error in execute_turn: %s", exc)
                    result, meta = f"Execution error: {exc}", {"speed": "0 t/s", "duration": "0s", "tokens": 0, "thinking": thinking}
                finally:
                    PHONE_QUEUE.task_done()

                store_result(
                    task_id,
                    "done",
                    result,
                    meta,
                )

                # User activity resets the idle interval.
                next_heartbeat = (
                    time.monotonic() + HEARTBEAT_INTERVAL
                )

                continue

            # --------------------------------------------
            # PRIORITY 2: AUTONOMOUS HEARTBEAT
            # --------------------------------------------

            now = time.monotonic()

            if now < next_heartbeat:
                continue

            # Check battery and heavy gaming/3D processes
            should_sleep, sleep_reason = check_power_and_apps()
            if should_sleep:
                LOG.debug(
                    "Heartbeat deferred: %s",
                    sleep_reason,
                )
                next_heartbeat = now + 60
                continue

            # Fail closed if CPU load cannot be measured.
            if (
                latest_cpu_load is None
                or latest_cpu_load >= CPU_IDLE_THRESHOLD
            ):
                LOG.debug(
                    "Heartbeat deferred: CPU busy/unknown"
                )

                # Retry CPU check later, not continuously.
                next_heartbeat = now + 60
                continue

            cancel = threading.Event()

            # Atomic check-and-install prevents losing an
            # incoming phone preemption signal.
            with STATE_LOCK:
                if not PHONE_QUEUE.empty():
                    continue

                ACTIVE_HEARTBEAT_CANCEL = cancel

            try:
                LOG.info(
                    "Heartbeat started; CPU load %.1f%%",
                    latest_cpu_load * 100,
                )

                result, meta = execute_turn(
                    "HEARTBEAT",
                    heartbeat=True,
                    cancel=cancel,
                    thinking="low",
                )

                LOG.info(
                    "Heartbeat result: %s",
                    result[:160],
                )

            finally:
                with STATE_LOCK:
                    ACTIVE_HEARTBEAT_CANCEL = None

                next_heartbeat = (
                    time.monotonic() + HEARTBEAT_INTERVAL
                )

    except KeyboardInterrupt:
        LOG.info("Shutdown requested")

    finally:
        server.shutdown()
        server.server_close()

        LOG.info("Operator stopped")


# ============================================================
# 14. STARTUP INTEGRITY CHECKS
# ============================================================

def startup_checks():
    """
    Refuse unsafe or incomplete startup.

    No automatic creation of security-critical instructions.
    No automatic modification of persistent identity files.
    """

    if os.name != "nt":
        raise SystemExit(
            "This E:\\sandbox configuration requires Windows"
        )

    if not os.getenv("ORCHESTRATOR_TOKEN"):
        raise SystemExit(
            "Set ORCHESTRATOR_TOKEN before startup"
        )

    if len(os.getenv("ORCHESTRATOR_TOKEN", "")) < 24:
        raise SystemExit(
            "ORCHESTRATOR_TOKEN must contain >=24 characters"
        )

    if not ROOT.is_dir():
        raise SystemExit(
            "Sandbox directory does not exist"
        )

    if is_reparse_point(ROOT):
        raise SystemExit(
            "Sandbox root must not be a symlink or junction"
        )

    required = [
        "gpt6-operator.md",
        "core_soul.md",
        "active_projects.md",
        "journal.md",
    ]

    for name in required:
        path = sandbox_path(name)

        if not path.is_file():
            raise SystemExit(
                f"Required sandbox file missing: {name}"
            )

    # Ensure model instructions exist and are readable.
    load_skill()

    # Refuse startup if core state is unreadable.
    sandbox_file_io(
        "read",
        "core_soul.md",
        limit=MAX_STATE_BYTES,
    )

    sandbox_file_io(
        "read",
        "active_projects.md",
        limit=MAX_STATE_BYTES,
    )

    LOG.info("Sandbox validation successful")
    LOG.info("Model endpoint: %s", LLAMA_URL)
    LOG.info("Maximum turn duration: %ds", TURN_TIMEOUT)
    LOG.info("Maximum turn tokens: %d", MAX_TURN_TOKENS)
    LOG.info("Heartbeat interval: %ds", HEARTBEAT_INTERVAL)


# ============================================================
# 15. ENTRY POINT
# ============================================================

if __name__ == "__main__":
    startup_checks()
    run_daemon()

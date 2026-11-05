"""Select the custody capability from a fixture's local wallet-create URL."""
import base64
import re
import sys
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def capability(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError("invalid custody capability")
    decoded = base64.urlsafe_b64decode(value + "=")
    if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("invalid custody capability")


def custody_launch_url(raw, port=18734):
    launch = urlsplit(raw)
    if (any(c.isspace() for c in raw) or launch.scheme != "http"
            or launch.netloc != f"localhost:{port}" or "?" in raw.split("#", 1)[0]):
        raise ValueError("invalid local custody origin")
    fields = parse_qsl(launch.fragment, strict_parsing=True)
    if launch.path == "/ceremony/" and len(fields) == 1 and fields[0][0] == "cap":
        capability(fields[0][1])
        return raw  # A fragment capability is authority, not UI routing.
    if not launch.path.startswith("/ceremony/"):
        raise ValueError("invalid local custody path")
    capability(launch.path.removeprefix("/ceremony/"))
    if not launch.fragment:
        return raw
    if len(fields) != 1 or fields[0][0] != "setup":
        raise ValueError("unknown custody fragment")
    bridge = urlsplit(fields[0][1])
    if (bridge.scheme != "http" or bridge.hostname != "127.0.0.1"
            or bridge.port is None or bridge.port == 0
            or bridge.netloc != f"127.0.0.1:{bridge.port}"
            or bridge.query or bridge.fragment
            or not re.fullmatch(r"/onboarding/[0-9a-f]{64}/", bridge.path)):
        raise ValueError("invalid local setup bridge")
    return urlunsplit(launch._replace(fragment=""))


if __name__ == "__main__":
    try:
        print(custody_launch_url(sys.stdin.read(), int(sys.argv[1]) if len(sys.argv) == 2 else 18734))
    except (ValueError, TypeError):
        sys.exit("unsupported local custody launch URL")

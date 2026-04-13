"""Token generation and verification (SEC-REV-2, SEC-REV-5)."""

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC


@dataclass
class Token:
    """Parsed token payload."""

    admin_id: int
    ip: str
    issued_at: int
    expires_at: int
    nonce: bytes
    token_bytes: bytes  # Full raw token for HMAC verification


class TokenError(Exception):
    """Token validation error."""

    pass


def mint_token(
    admin_id: int,
    ip: str,
    nonce: bytes,
    hmac_secret: str,
    token_ttl_seconds: int = 60,
) -> tuple[str, int]:
    """
    Mint a new session token.

    Returns: (token_base64, expires_at_unix)

    Token structure (104 bytes raw):
    - admin_id (8B): u64 little-endian
    - ip (16B): 16 bytes (IPv4 zero-padded or IPv6)
    - issued_at (8B): u64 little-endian unix seconds
    - expires_at (8B): u64 little-endian unix seconds
    - nonce (32B): random bytes, single-use key
    - hmac_sha256 (32B): HMAC-SHA256(body, hmac_secret)

    The token is never placed in a URL (SEC-REV-2); it's only sent in the
    WebSocket auth frame after the handshake-challenge completes.
    """
    now = int(time.time())
    expires_at = now + token_ttl_seconds

    # Normalize IP to 16 bytes (IPv4 zero-padded, IPv6 as-is)
    ip_bytes = _normalize_ip(ip)

    # Construct token body (72 bytes: admin_id + ip + issued_at + expires_at + nonce)
    body = struct.pack("<Q", admin_id)  # admin_id: 8B
    body += ip_bytes  # ip: 16B
    body += struct.pack("<Q", now)  # issued_at: 8B
    body += struct.pack("<Q", expires_at)  # expires_at: 8B
    body += nonce  # nonce: 32B

    # Compute HMAC-SHA256 over body
    secret_bytes = bytes.fromhex(hmac_secret)
    h = hmac.new(secret_bytes, body, hashlib.sha256)
    hmac_digest = h.digest()  # 32B

    # Full token: body + hmac
    token_bytes = body + hmac_digest  # 104B total

    # Encode as base64 URL-safe (no padding stripped per standard base64)
    token_b64 = base64.urlsafe_b64encode(token_bytes).decode("ascii")

    return token_b64, expires_at


def verify_token(
    token_b64: str,
    ip: str,
    hmac_secret: str,
    nonce_consumed_check: callable,
) -> Token:
    """
    Verify token in strict order (SEC-REV-5).

    Verification order (any failure -> single TokenError):
    1. Parse / base64 decode
    2. expires_at > now
    3. nonce not previously consumed (nonce_consumed_check returns True if already consumed)
    4. ip matches X-Real-IP (X-Real-IP set by nginx)
    5. HMAC valid

    Args:
        token_b64: Base64-encoded token
        ip: Client IP from X-Real-IP header
        hmac_secret: Hex-encoded HMAC secret
        nonce_consumed_check: Callable(nonce: bytes) -> bool; True = already consumed
                             (can be sync or async; for async, wrap in asyncio.run())

    Returns: Token object with admin_id, ip, issued_at, expires_at, nonce

    Raises: TokenError on any verification failure (single error, no detail leakage)
    """
    try:
        # Step 1: Parse / base64 decode
        token_bytes = base64.urlsafe_b64decode(token_b64.encode("ascii"))
        if len(token_bytes) != 104:
            raise TokenError("invalid token")

        # Unpack fields
        admin_id = struct.unpack("<Q", token_bytes[0:8])[0]
        ip_bytes = token_bytes[8:24]
        issued_at = struct.unpack("<Q", token_bytes[24:32])[0]
        expires_at = struct.unpack("<Q", token_bytes[32:40])[0]
        nonce = token_bytes[40:72]
        provided_hmac = token_bytes[72:104]

        body = token_bytes[0:72]

        # Step 2: Check expiration
        now = int(time.time())
        if expires_at <= now:
            raise TokenError("invalid token")

        # Step 3: Check nonce not consumed
        # Call nonce_consumed_check(nonce) to reject if already used.
        # Raises TokenError if nonce is consumed (returns True).
        if nonce_consumed_check(nonce):
            raise TokenError("invalid token")

        # Step 4: Check IP binding
        ip_normalized = _normalize_ip(ip)
        if ip_bytes != ip_normalized:
            raise TokenError("invalid token")

        # Step 5: Verify HMAC
        secret_bytes = bytes.fromhex(hmac_secret)
        h = hmac.new(secret_bytes, body, hashlib.sha256)
        expected_hmac = h.digest()
        if not hmac.compare_digest(provided_hmac, expected_hmac):
            raise TokenError("invalid token")

        # Return parsed token
        return Token(
            admin_id=admin_id,
            ip=ip,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            token_bytes=token_bytes,
        )

    except TokenError:
        raise
    except Exception:
        # All other errors map to generic TokenError (no detail leakage)
        raise TokenError("invalid token")


def _normalize_ip(ip: str) -> bytes:
    """
    Normalize IP to 16 bytes.

    IPv4: zero-padded to 16 bytes (e.g., 127.0.0.1 -> 12 zero bytes + 4 IPv4 bytes)
    IPv6: raw 16 bytes
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return b"\x00" * 12 + addr.packed  # 16B total
        else:  # IPv6
            return addr.packed  # 16B
    except ValueError as e:
        raise TokenError(f"invalid ip: {ip}") from e

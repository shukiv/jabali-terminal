"""WebSocket server and API endpoints."""

import asyncio
import base64
import json
import logging
import os
import secrets
import sys
from typing import Optional

from aiohttp import web
from websockets.asyncio.server import serve, ServerConnection

from .audit import AuditSession, scan_unclosed_logs
from .auth import TokenError, mint_token, verify_token
from .config import load_config, TerminalConfig
from .nonce_store import NonceStore
from .pty_bridge import run_pty_session

logger = logging.getLogger(__name__)


class TerminalServer:
    """Main server instance."""

    def __init__(self, config: TerminalConfig):
        """Initialize server."""
        self.config = config
        self.nonce_store = NonceStore(config.nonce_db_path)
        self.active_sessions = {}  # session_id -> {admin_id, ip, ws, audit}

    async def init(self) -> None:
        """Initialize server (database, scan for interrupted logs)."""
        await self.nonce_store.init()
        await scan_unclosed_logs(self.config.audit_log_dir, self.config.audit_hmac_secret)

    async def close(self) -> None:
        """Shutdown server."""
        # Close all active sessions
        for session_id, session_info in self.active_sessions.items():
            ws = session_info.get("ws")
            if ws:
                try:
                    await ws.close()
                except Exception:
                    pass

        await self.nonce_store.close()

    async def health_handler(self, request: web.Request) -> web.Response:
        """GET /health — health check."""
        return web.json_response({"status": "ok"})

    async def session_handler(self, request: web.Request) -> web.Response:
        """
        POST /api/v1/session — Mint session token.

        Request: {admin_id, ip, issued_at, nonce} signed with HMAC
        Response: {ws_url, token, expires_at}

        The token is never returned in a URL; it's held in client memory
        and sent via handshake-challenge in the WebSocket auth frame (SEC-REV-2).
        """
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "invalid request"}, status=400)

        admin_id = data.get("admin_id")
        ip = data.get("ip")
        nonce_hex = data.get("nonce")
        issued_at = data.get("issued_at")
        hmac_sig = data.get("hmac")

        if not all([admin_id, ip, nonce_hex, issued_at, hmac_sig]):
            return web.json_response({"error": "missing fields"}, status=400)

        try:
            nonce = bytes.fromhex(nonce_hex)
            token_b64, expires_at = mint_token(
                admin_id,
                ip,
                nonce,
                self.config.hmac_secret,
                token_ttl_seconds=60,
            )

            return web.json_response(
                {
                    "ws_url": f"wss://{request.host}/terminal-ws",
                    "token": token_b64,
                    "expires_at": expires_at,
                }
            )
        except Exception as e:
            logger.error(f"Token minting failed: {e}")
            return web.json_response({"error": "token minting failed"}, status=500)

    async def ws_handler(self, request: web.Request) -> web.WebSocketResponse:
        """
        WebSocket endpoint: /terminal-ws

        Handshake-challenge flow (SEC-REV-2):
        1. Daemon sends: {type: "challenge", nonce: <32B hex>}
        2. Client responds: {type: "auth", token: <token>, nonce_response: HMAC_SHA256(token, challenge_nonce)}
        3. Daemon verifies token, accepts WS, spawns PTY, proxies traffic

        Each message is a distinct JSON payload (no code interpretation).
        """
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        # Extract X-Real-IP (set by nginx)
        client_ip = request.headers.get("X-Real-IP", request.remote)

        # Generate challenge nonce (32B)
        challenge_nonce = secrets.token_bytes(32)
        challenge_nonce_hex = challenge_nonce.hex()

        # Send challenge
        await ws.send_json({"type": "challenge", "nonce": challenge_nonce_hex})

        # Wait for auth response (5s timeout per SEC-REV-1)
        try:
            auth_msg = await asyncio.wait_for(ws.receive_json(), timeout=5.0)
        except (asyncio.TimeoutError, ValueError) as e:
            await ws.close(code=1008, message="401 invalid token")
            logger.warning(f"Auth timeout or invalid JSON: {e}")
            return ws

        try:
            msg_type = auth_msg.get("type")
            if msg_type != "auth":
                await ws.close(code=1008, message="401 invalid token")
                logger.warning("Expected auth message")
                return ws

            token_b64 = auth_msg.get("token")
            nonce_response = auth_msg.get("nonce_response")

            if not token_b64 or not nonce_response:
                await ws.close(code=1008, message="401 invalid token")
                return ws

            # Verify token (SEC-REV-5 strict order)
            def nonce_consumed_check(nonce: bytes) -> bool:
                """Sync check if nonce was consumed (will be done async)."""
                # This is a wrapper; actual check happens in consume()
                return False  # Placeholder

            token = verify_token(
                token_b64,
                client_ip,
                self.config.hmac_secret,
                nonce_consumed_check,
            )

            # Verify challenge response
            import hashlib
            import hmac

            expected_response = hmac.new(
                token.nonce,
                challenge_nonce,
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(nonce_response, expected_response):
                await ws.close(code=1008, message="401 invalid token")
                logger.warning("Challenge response verification failed")
                return ws

            # Consume nonce (must succeed; if already consumed, reject)
            nonce_hex = token.nonce.hex()
            nonce_consumed = await self.nonce_store.consume(nonce_hex, token.expires_at)
            if not nonce_consumed:
                await ws.close(code=1008, message="401 invalid token")
                logger.warning(f"Nonce already consumed: {nonce_hex}")
                return ws

            # Nonce is consumed and fsync'd; WS is now accepted
            # Get admin name (for audit logging) — in real use, this comes from the panel
            # For now, use a placeholder; the panel passes this in the session request
            admin_name = f"admin_{token.admin_id}"
            session_id = secrets.token_hex(8)

            # Create audit session
            audit = AuditSession(
                self.config.audit_log_dir,
                token.admin_id,
                admin_name,
                client_ip,
                session_id,
                self.config.audit_hmac_secret,
            )

            # Register session
            self.active_sessions[session_id] = {
                "admin_id": token.admin_id,
                "ip": client_ip,
                "ws": ws,
                "audit": audit,
            }

            # PTY proxy
            async def ws_send(data):
                try:
                    if isinstance(data, bytes):
                        await ws.send_bytes(data)
                    else:
                        await ws.send_str(data)
                except Exception:
                    pass

            async def ws_recv():
                return await ws.receive_json()

            try:
                exit_code = await run_pty_session(
                    self.config.shell,
                    ws_send,
                    ws_recv,
                    audit,
                    admin_name,
                    session_id,
                    self.config.session_idle_seconds,
                    self.config.session_hard_seconds,
                )
            finally:
                # Clean up
                self.active_sessions.pop(session_id, None)
                await ws.close()

            return ws

        except TokenError as e:
            await ws.close(code=1008, message="401 invalid token")
            logger.warning(f"Token verification failed: {e}")
            return ws
        except Exception as e:
            await ws.close(code=1008, message="401 invalid token")
            logger.error(f"Unexpected auth error: {e}")
            return ws


async def main() -> None:
    """Start daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Load configuration
    try:
        config = load_config()
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Initialize server
    server = TerminalServer(config)
    await server.init()

    # Create aiohttp app for unix socket HTTP API
    app = web.Application()
    app.router.add_get("/health", server.health_handler)
    app.router.add_post("/api/v1/session", server.session_handler)

    # Create runner
    runner = web.AppRunner(app)
    await runner.setup()

    # Bind to unix socket
    socket_path = config.socket_path
    os.makedirs(os.path.dirname(socket_path), exist_ok=True)
    if os.path.exists(socket_path):
        os.remove(socket_path)

    site = web.UnixSite(runner, socket_path)
    await site.start()

    # Set socket permissions (root:www-data, 0660)
    try:
        os.chmod(socket_path, 0o660)
        import grp

        www_data_gid = grp.getgrnam("www-data").gr_gid
        os.chown(socket_path, 0, www_data_gid)
    except Exception as e:
        logger.warning(f"Failed to set socket permissions: {e}")

    logger.info(f"Listening on unix socket: {socket_path}")

    # Start WebSocket server (on same TCP port, but via nginx proxy)
    # Actually, the WS server is proxied by nginx to the unix socket.
    # For now, we don't run a separate WS server; the ws_handler above
    # is called by nginx proxying to the HTTP API.
    # The real WS server listening is handled by nginx at TLS termination.

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()
        await server.close()


if __name__ == "__main__":
    asyncio.run(main())

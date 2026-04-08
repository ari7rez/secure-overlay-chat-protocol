"""
Simple WebSocket server for SOCP overlay.

Features:
- Accepts client connections (USER_HELLO, envelopes)
- Accepts server/peer connections (SERVER_HELLO / SERVER_WELCOME)
- Outgoing bootstrap connections to other peers
- Spawns per-connection task handling
- Uses ServerHandlers (in src/server/handlers.py) to process envelopes
"""

import argparse
import asyncio
import json
import logging
import pathlib
import signal
from typing import Dict, Optional

import websockets

from .routing import State
from .handlers import ServerHandlers

# Protocol constants (must match other modules)
SERVER_HELLO = "SERVER_HELLO"
SERVER_WELCOME = "SERVER_WELCOME"

# default reconnect/backoff settings
BOOTSTRAP_RETRY_BASE = 1.0
BOOTSTRAP_RETRY_MAX = 30.0


def setup_logging(name: str, level: str = "INFO", logfile: Optional[str] = None):
    lvl = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s | %(name)s | %(levelname)s | %(message)s"

    # Always log to console + file
    handlers = [logging.StreamHandler()]
    log_path = logfile or "server.log"
    handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(level=lvl, format=fmt, handlers=handlers)
    logger = logging.getLogger(name)
    logger.info("logging to console and %s (level=%s)",
                log_path, level.upper())
    return logger


class ServerApp:
    def __init__(self, server_id: str, port: int, bootstrap: list[str], logger: logging.Logger):
        self.server_id = server_id
        self.port = port
        self.bootstrap = bootstrap or []
        self.log = logger

        # application state
        self.state = State(server_id=server_id)
        self.handlers = ServerHandlers(
            state=self.state, logger=self.log.getChild("handlers"))

        # track tasks
        self._peer_tasks: Dict[str, asyncio.Task] = {}
        self._accept_task: Optional[asyncio.Task] = None
        self._served = None  # serve object for websockets.serve

        # run flag
        self._stopping = False

    # Accept and dispatch
    async def _accept(self, ws: websockets.WebSocketServerProtocol, path: str):
        """
        Accepts a new connection. The same accept path is used for:
        - clients (USER_HELLO envelopes)
        - peers (SERVER_HELLO handshake)
        We handle both on the same socket.
        """
        remote = getattr(ws, "remote_address", None)
        self.log.info("connection opened: %s", remote)
        peer_id = None

        # create a simple send wrapper for use by handlers
        async def send_back(obj):
            try:
                await ws.send(json.dumps(obj))
            except Exception as e:
                self.log.debug("send_back failed: %s", e)

        try:
            # The connection will send JSON messages. We don't pre-classify here;
            # handlers._handle_server_msg will process SERVER_* messages specially.
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    self.log.debug("non-json from %s: %s", remote, raw)
                    continue

                mtype = msg.get("type")

                # If this is a server HELLO from a peer, handle handshake quickly.
                if mtype == SERVER_HELLO:
                    # record temporary ws mapping for handshake
                    peer_id = msg.get("id")
                    if peer_id:
                        self.state.peers[peer_id] = ws
                        self.log.info("peer joined (incoming): %s", peer_id)
                        # Immediately reply with SERVER_WELCOME so peer knows our id.
                        await send_back({"type": SERVER_WELCOME, "id": self.server_id})
                        # Do not clear user_locations on disconnect (see design)
                    else:
                        await send_back({"type": "ERROR", "error": "missing_id"})
                    continue

                # If peer sends SERVER_WELCOME as part of handshake
                if mtype == SERVER_WELCOME:
                    peer_id = msg.get("id")
                    if peer_id:
                        self.state.peers[peer_id] = ws
                        self.log.info(
                            "handshake complete (incoming welcome) with peer: %s", peer_id)
                    continue

                # Otherwise dispatch to handlers (it knows how to process SERVER_* messages too)
                try:
                    await self.handlers.handle(msg, send_back, ws)
                except Exception as e:
                    self.log.exception("error handling msg: %s", e)

        except websockets.ConnectionClosed as ex:
            self.log.info("connection closed: %s (%s)",
                          remote, getattr(ex, "code", "n/a"))
        except Exception as e:
            self.log.exception("accept loop error: %s", e)
        finally:
            # Clean up peer mapping for this websocket, but keep user_locations intact.
            if peer_id:
                # remove peer socket but keep locations mapping (do not wipe them)
                old = self.state.peers.pop(peer_id, None)
                self.log.info("peer disconnected: %s", peer_id)
            else:
                self.log.info("client disconnected: %s", remote)

    async def start_server(self):
        """Start the main listening server and the bootstrap connector tasks."""
        self.log.info("%s listening on :%s", self.server_id, self.port)
        self._served = websockets.serve(self._accept, "0.0.0.0", self.port)
        # context manager style
        self._accept_task = asyncio.create_task(self._served.__aenter__())

        # start bootstrap connectors for each bootstrap peer
        for url in self.bootstrap:
            t = asyncio.create_task(self._bootstrap_connect_loop(url))
            self._peer_tasks[url] = t

    async def stop(self):
        self._stopping = True
        self.log.info("shutting down server %s", self.server_id)
        # cancel peer tasks
        for url, t in list(self._peer_tasks.items()):
            t.cancel()
        if self._accept_task:
            self._accept_task.cancel()
        # close websockets server
        if self._served:
            try:
                await self._served.__aexit__(None, None, None)
            except Exception:
                pass

    # Outgoing peer connect loop 
    async def _bootstrap_connect_loop(self, url: str):
        """
        Continuously try to connect to the peer URL, handshake, and process incoming peer messages
        over the outgoing socket. On disconnect, keep location mapping present (we rely on retries).
        """
        name = f"bootstrap:{url}"
        backoff = BOOTSTRAP_RETRY_BASE
        while not self._stopping:
            try:
                self.log.info("connect to peer url=%s", url)
                async with websockets.connect(url) as ws:
                    # Send SERVER_HELLO
                    await ws.send(json.dumps({"type": SERVER_HELLO, "id": self.server_id}))
                    # wait for SERVER_WELCOME
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                        msg = json.loads(raw)
                        if msg.get("type") == SERVER_WELCOME:
                            peer_id = msg.get("id")
                            if peer_id:
                                self.state.peers[peer_id] = ws
                                self.log.info("connected to peer url=%s", url)
                                # After handshake, re-advertise local users by sending SERVER_USER_ADVERT. The handlers module will respond to SERVER_WELCOME by sending adverts too, but we ensure both sides quickly learn local users. We also accept SERVER_USER_ADVERT messages below via handlers.handle.
                            else:
                                self.log.warning(
                                    "peer welcome missing id from %s", url)
                        else:
                            self.log.debug(
                                "unexpected handshake reply: %s", msg)
                    except asyncio.TimeoutError:
                        self.log.warning(
                            "no SERVER_WELCOME from %s (timeout)", url)

                    # Now process incoming messages from this peer using handlers
                    async for raw in ws:
                        try:
                            msg = json.loads(raw)
                        except Exception:
                            self.log.debug("non-json peer msg: %s", raw)
                            continue
                        # Use same handlers to interpret SERVER_* messages
                        try:
                            # handlers.handle will place the peer mapping in state as needed
                            await self.handlers.handle(msg, lambda o: ws.send(json.dumps(o)), ws)
                        except Exception as e:
                            self.log.exception(
                                "error handling peer msg: %s", e)

            except asyncio.CancelledError:
                return
            except Exception as e:
                self.log.warning(
                    "peer connect failed %s: %s (retrying in %.1fs)", url, e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 1.8, BOOTSTRAP_RETRY_MAX)
                continue

            # if the connection closed cleanly, backoff reset
            backoff = BOOTSTRAP_RETRY_BASE
            self.log.info(
                "disconnected from peer %s; will retry in %.1fs", url, backoff)
            await asyncio.sleep(backoff)

    # Utility run/CLI
    async def run_forever(self):
        await self.start_server()
        # Wait until cancelled
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--id", required=True,
                    help="server identifier (e.g., SrvA)")
    ap.add_argument("--port", type=int, required=True, help="listen port")
    ap.add_argument("--bootstrap", required=False,
                    help="path to bootstrap YAML (list of peer URLs)")
    ap.add_argument("--log-level", default="INFO",
                    help="logging level (DEBUG/INFO...)")
    ap.add_argument("--log-file", default=None,
                    help="optional file to write logs to")
    args = ap.parse_args()

    logger = setup_logging("socp." + args.id, args.log_level, args.log_file)

    # Load bootstrap peers from YAML if provided (simple parsing)
    bpeers = []
    if args.bootstrap:
        try:
            import yaml

            p = yaml.safe_load(pathlib.Path(args.bootstrap).read_text())
            if isinstance(p, dict):
                bpeers = p.get("peers") or []
            elif isinstance(p, list):
                bpeers = p
        except Exception as e:
            logger.warning("cannot read bootstrap file %s: %s",
                           args.bootstrap, e)

    app = ServerApp(server_id=args.id, port=args.port,
                    bootstrap=bpeers, logger=logger)

    loop = asyncio.get_event_loop()

    # handle SIGTERM/SIGINT to shutdown gracefully
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(
                sig, lambda: asyncio.create_task(shutdown(loop, app, logger)))
        except NotImplementedError:
            # Windows event loop may not support add_signal_handler
            pass

    try:
        loop.run_until_complete(app.run_forever())
    except KeyboardInterrupt:
        logger.info("keyboard interrupt")
    finally:
        # ensure cleanup
        loop.run_until_complete(shutdown(loop, app, logger))


async def shutdown(loop, app: ServerApp, logger):
    logger.info("shutdown requested")
    await app.stop()
    # give tasks a moment
    await asyncio.sleep(0.1)
    for task in asyncio.all_tasks():
        if task is asyncio.current_task():
            continue
        task.cancel()
    await asyncio.sleep(0.1)
    loop.stop()


if __name__ == "__main__":
    main()

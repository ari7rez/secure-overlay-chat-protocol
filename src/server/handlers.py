import asyncio
import time
import json
import logging
from typing import Dict, Any, Callable, Optional
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.server.routing import State
from src.protocol.messages import validate_envelope
from src.crypto.rsa_crypto import load_public_key, verify_pss, b64u_decode
from src.crypto.canonical import canonical_bytes_for_sign
from src.server.database import upsert_user

FRESHNESS_MS = 120_000  # 120 seconds


class ServerHandlers:
    def __init__(self, state: State, logger: logging.Logger):
        self.st = state
        self.log = logger
        self.user_pubkeys: Dict[str, str] = {}  # cache user -> PEM

    async def handle(self, msg: Dict[str, Any], send_func: Callable[[Dict[str, Any]], None], ws=None):
        mtype = msg.get("type")

        # Server-to-server control messages (not user envelopes)
        if mtype in {"SERVER_HELLO", "SERVER_WELCOME", "SERVER_USER_ADVERT", "SERVER_DELIVER"}:
            return await self._handle_server_msg(msg, send_func, ws)

        # Client envelopes: validate & freshness
        if not validate_envelope(msg):
            self.log.warning("bad_envelope dropped")
            return await send_func({"type": "ERROR", "error": "bad_envelope"})

        now_ms = int(time.time() * 1000)
        if abs(now_ms - int(msg.get("ts", 0))) > FRESHNESS_MS:
            self.log.warning("stale message dropped id=%s", msg.get("id"))
            return

        if mtype == "USER_HELLO":
            await self._user_hello(msg, send_func, ws)
        elif mtype == "LIST_REQUEST":
            await self._list_request(send_func)
        elif mtype == "MSG_DIRECT":
            await self._msg_direct(msg, send_func)
        elif mtype == "MSG_BROADCAST":
            await self._msg_broadcast(msg, send_func, inbound_peer=None)
        elif mtype in {"FILE_START", "FILE_CHUNK", "FILE_END"}:
            await self._file_route(msg, send_func)
        elif mtype == "PUBKEY_REQUEST":
            await self._pubkey_request(msg, send_func)
        else:
            await send_func({"type": "ERROR", "error": "unhandled_type", "got": mtype})

    # User messages (from clients)
    async def _user_hello(self, msg, send, ws):
        user = msg["from"]
        pem = msg["payload"].get("pubkey", "")
        if not pem:
            return await send({"type": "ERROR", "error": "missing_pubkey"})

        # Enforce RSA-4096
        try:
            pub = load_public_key(pem)
            if not isinstance(pub, RSAPublicKey) or getattr(pub, "key_size", 0) != 4096:
                return await send({"type": "ERROR", "error": "weak_or_invalid_key"})
        except Exception as e:
            self.log.warning("bad_pubkey from=%s err=%s", user, e)
            return await send({"type": "ERROR", "error": "bad_pubkey"})

        # Record mappings
        self.user_pubkeys[user] = pem
        self.st.local_users.add(user)
        self.st.user_ws[user] = ws
        self.st.user_locations[user] = self.st.server_id
        upsert_user(user, pem, int(time.time()))
        self.log.info("user connected: %s (RSA-4096 OK)", user)

        # Welcome with current users
        users_list = [{"user": u, "pubkey": self.user_pubkeys[u]}
                      for u in sorted(self.user_pubkeys)]
        await send({"type": "WELCOME", "you": user, "server": self.st.server_id, "users": users_list})

        # Notify local others
        added = {"type": "USER_ADDED", "user": user, "pubkey": pem}
        for u, w in list(self.st.user_ws.items()):
            if u != user:
                try:
                    await w.send(json.dumps(added))
                except Exception:
                    pass

        # Gossip to peers: user location / pubkey
        advert = {"type": "SERVER_USER_ADVERT", "user": user,
                  "pubkey": pem, "at": self.st.server_id}
        await self._fanout_to_peers(advert, exclude=None)

    async def _list_request(self, send):
        users = sorted(self.st.local_users)
        self.log.info("LIST_RESPONSE count=%d", len(users))
        await send({"type": "LIST_RESPONSE", "users": users, "count": len(users)})

    async def _msg_direct(self, msg, send):
        sender = msg["from"]
        dest = msg["to"]

        # Verify transport signature (payload only) if we know sender
        if sender in self.user_pubkeys:
            pub = load_public_key(self.user_pubkeys[sender])
            if not verify_pss(pub, canonical_bytes_for_sign(msg["payload"]), b64u_decode(msg["sig"])):
                self.log.warning("bad transport sig DM id=%s", msg.get("id"))
                return

        # Local deliver
        dest_ws = self.st.user_ws.get(dest)
        if dest_ws:
            dm = {"type": "DM", "from": sender, "to": dest,
                  "ts": msg["ts"], "id": msg["id"], "payload": msg["payload"]}
            await dest_ws.send(json.dumps(dm))
            await send({"type": "DELIVERED_LOCAL", "to": dest})
            self.log.info("DM delivered: %s -> %s id=%s",
                          sender, dest, msg.get("id"))
            return

        # Forward by user location
        await self._forward_to_user(dest, msg, send)

    async def _msg_broadcast(self, msg, send, inbound_peer: Optional[str]):
        sender = msg["from"]
        payload = msg.get("payload", {})
        ttl = int(payload.get("ttl", 8))
        text = payload.get("text", "")

        # Verify transport signature if we know sender
        if sender in self.user_pubkeys:
            pub = load_public_key(self.user_pubkeys[sender])
            if not verify_pss(pub, canonical_bytes_for_sign(payload), b64u_decode(msg["sig"])):
                self.log.warning("bad broadcast sig id=%s", msg.get("id"))
                return

        # TTL/dedupe
        if ttl <= 0:
            self.log.debug("broadcast dropped ttl<=0 id=%s", msg.get("id"))
            return
        if self.st.mark_seen(msg["id"]):
            self.log.debug("broadcast duplicate dropped id=%s", msg["id"])
            return

        # Local fan-out
        for u, w in list(self.st.user_ws.items()):
            if u == sender:
                continue
            bc = {"type": "ALL", "from": sender,
                  "ts": msg["ts"], "id": msg["id"], "text": text}
            try:
                await w.send(json.dumps(bc))
            except Exception:
                pass

        # Forward to peers (except the one we received from)
        fwd = dict(msg)
        fwd["payload"] = dict(payload)
        fwd["payload"]["ttl"] = ttl - 1
        wrapper = {"type": "SERVER_DELIVER",
                   "from_server": self.st.server_id, "to_server": "*", "inner": fwd}
        for pid, pws in list(self.st.peers.items()):
            if inbound_peer and pid == inbound_peer:  # avoid echo
                continue
            try:
                await pws.send(json.dumps(wrapper))
            except Exception:
                pass

    # FILE routing with dedupe + logs 
    async def _file_route(self, msg, send):
        sender, dest = msg["from"], msg["to"]
        payload = msg.get("payload", {})
        mtype = msg.get("type")
        mid = msg.get("id")

        # Dedupe by envelope ID
        if self.st.mark_seen(mid):
            self.log.debug("dup %s dropped id=%s", mtype, mid)
            return

        # Verify transport signature if we know sender
        if sender in self.user_pubkeys:
            pub = load_public_key(self.user_pubkeys[sender])
            if not verify_pss(pub, canonical_bytes_for_sign(payload), b64u_decode(msg["sig"])):
                self.log.warning(
                    "bad file transport sig from=%s type=%s", sender, mtype)
                return

        loc = self.st.user_locations.get(dest)
        self.log.debug("FILE %s id=%s route-check dest=%s loc=%s local=%s",
                       mtype, mid, dest, loc, dest in self.st.local_users)

        # Local deliver
        dest_ws = self.st.user_ws.get(dest)
        if dest_ws:
            self.log.debug("FILE %s id=%s deliver-local %s->%s",
                           mtype, mid, sender, dest)
            fm = {"type": mtype, "from": sender, "to": dest,
                  "ts": msg["ts"], "id": mid, "payload": payload}
            await dest_ws.send(json.dumps(fm))
            await send({"type": "FILE_ACK", "stage": mtype, "to": dest})
            return

        # Forward to peer (with small retries handled in _forward_to_user)
        await self._forward_to_user(dest, msg, send)

    async def _pubkey_request(self, msg, send):
        """Return PEM for requested user if known to this server."""
        target = (msg.get("payload") or {}).get("user")
        if not target:
            return await send({"type": "ERROR", "error": "missing_user"})
        pem = self.user_pubkeys.get(target)
        if pem:
            await send({"type": "PUBKEY_RESPONSE", "user": target, "pubkey": pem})
            self.log.info("PUBKEY_RESPONSE user=%s", target)
        else:
            await send({"type": "ERROR", "error": "unknown_user", "user": target})
            self.log.info("PUBKEY_REQUEST miss user=%s", target)

    # Peer messages (server-to-server) 
    async def _handle_server_msg(self, msg: Dict[str, Any], send_func, ws):
        t = msg["type"]
        if t == "SERVER_HELLO":
            peer_id = msg.get("id")
            if not peer_id:
                return await send_func({"type": "ERROR", "error": "missing_id"})
            self.st.peers[peer_id] = ws
            await send_func({"type": "SERVER_WELCOME", "id": self.st.server_id})
            self.log.info("peer joined: %s", peer_id)

        elif t == "SERVER_WELCOME":
            peer_id = msg.get("id")
            if peer_id:
                self.st.peers[peer_id] = ws
                self.log.info("handshake complete with peer: %s", peer_id)
                # Re-advertise all local users to this peer so it learns locations
                for u in sorted(self.st.local_users):
                    pem = self.user_pubkeys.get(u)
                    advert = {"type": "SERVER_USER_ADVERT", "user": u,
                              "pubkey": pem, "at": self.st.server_id}
                    try:
                        await ws.send(json.dumps(advert))
                        self.log.debug("re-advertised %s to %s", u, peer_id)
                    except Exception as e:
                        self.log.warning(
                            "re-advertise failed to %s: %s", peer_id, e)

        elif t == "SERVER_USER_ADVERT":
            user = msg.get("user")
            at = msg.get("at")
            pem = msg.get("pubkey")
            if user and at:
                self.st.user_locations[user] = at
                if pem:
                    self.user_pubkeys.setdefault(user, pem)
                self.log.debug("learned user location: %s@%s", user, at)

        elif t == "SERVER_DELIVER":
            inner = msg.get("inner") or {}
            itype = inner.get("type")
            if itype == "MSG_DIRECT":
                dest = inner.get("to")
                if dest in self.st.local_users:
                    await self._msg_direct(inner, lambda _: _)
                else:
                    await self._forward_to_user(dest, inner, lambda _: _)
            elif itype == "MSG_BROADCAST":
                inbound = msg.get("from_server")
                await self._msg_broadcast(inner, lambda _: _, inbound_peer=inbound)
            elif itype in {"FILE_START", "FILE_CHUNK", "FILE_END"}:
                dest = inner.get("to")
                if dest in self.st.local_users:
                    await self._file_route(inner, lambda _: _)
                else:
                    await self._forward_to_user(dest, inner, lambda _: _)
            else:
                pass

    # Utils 
    async def _fanout_to_peers(self, obj: dict, exclude: Optional[str]):
        for pid, pws in list(self.st.peers.items()):
            if exclude and pid == exclude:
                continue
            try:
                await pws.send(json.dumps(obj))
            except Exception:
                pass

    async def _forward_to_user(self, dest_user: str, inner_msg: dict, send_ack):
        """Forward inner_msg to the peer where dest_user lives, with small retries for transient drops."""
        peer_id = self.st.user_locations.get(dest_user)

        # If we don't know a location, fail fast
        if not peer_id or peer_id == self.st.server_id:
            await send_ack({"type": "ERROR", "error": "user_offline", "to": dest_user})
            self.log.info("deliver failed (unknown location): user=%s id=%s",
                          dest_user, inner_msg.get("id"))
            return

        attempts = 3
        delay = 0.3
        for i in range(attempts):
            pws = self.st.peers.get(peer_id)
            if not pws:
                await asyncio.sleep(delay)
                continue

            wrapper = {
                "type": "SERVER_DELIVER",
                "from_server": self.st.server_id,
                "to_server": peer_id,
                "inner": inner_msg,
            }
            try:
                await pws.send(json.dumps(wrapper))
                await send_ack({"type": "FORWARDED", "to_server": peer_id, "to_user": dest_user})
                self.log.info("forwarded to peer=%s user=%s type=%s id=%s (attempt=%d)",
                              peer_id, dest_user, inner_msg.get("type"), inner_msg.get("id"), i + 1)
                return
            except Exception as e:
                self.log.warning(
                    "forward attempt %d failed to %s: %s", i + 1, peer_id, e)
                await asyncio.sleep(delay)

        # All retries exhausted
        await send_ack({"type": "ERROR", "error": "user_offline", "to": dest_user})
        self.log.info("deliver failed after retries: user=%s id=%s",
                      dest_user, inner_msg.get("id"))

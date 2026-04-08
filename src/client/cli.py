import argparse
import asyncio
import json
import sys
import os
import hashlib
import websockets

from src.protocol.messages import new_envelope
from src.crypto.rsa_crypto import (
    rsa_oaep_decrypt,
    rsa_oaep_encrypt,
    b64u_decode,
    b64u,
    load_public_key,
    verify_pss,
    sign_pss,
)
from src.client.keystore import ensure_keys, load_priv, public_pem_str
from src.client.wire import sign_envelope, build_dm

# simple in-memory cache of user -> pubkey (PEM)
PUBS = {}

# file rx state: file_id -> {"name": str, "size": int, "sha256": str, "total": int, "got": int, "chunks": {}}
RX = {}

CHUNK_SIZE = 400                 # RSA-4096 + OAEP(SHA-256) safe plaintext size
MAX_SIZE = 50 * 1024 * 1024    # 50 MB cap
MAX_CHUNKS = 8192                # safety limit


def _pretty_server_message(msg: dict, raw: str):
    """Human-friendly rendering of misc server notifications."""
    t = msg.get("type", "")
    if t == "LIST_RESPONSE":
        users = msg.get("users") or []
        print(f"[users] {sorted(users)} (count={len(users)})")
        return
    if t == "DELIVERED_LOCAL":
        print(f"[info] delivered locally to {msg.get('to')}")
        return
    if t == "FORWARDED":
        print(
            f"[info] forwarded via {msg.get('to_server')} to {msg.get('to_user')}")
        return
    if t == "WELCOME":
        # handled separately already
        return
    # Fallback: compact view instead of raw JSON
    who = msg.get("from") or msg.get("server") or "server"
    what = t or "message"
    print(f"[{who}] {what}")


def _unique_download_path(name: str) -> str:
    """Return a unique path under downloads/ to avoid overwriting existing files."""
    os.makedirs("downloads", exist_ok=True)
    base = os.path.abspath(os.path.join("downloads", name))
    if not os.path.exists(base):
        return base
    root, ext = os.path.splitext(base)
    i = 1
    while True:
        cand = f"{root}.{i}{ext}"
        if not os.path.exists(cand):
            return cand
        i += 1


async def run(url: str, user: str):
    ensure_keys()
    priv = load_priv()
    my_pub_pem = public_pem_str()

    async with websockets.connect(url) as ws:
        # Introduce ourselves + pubkey
        hello = new_envelope("USER_HELLO", user, "server",
                             {"pubkey": my_pub_pem})
        sign_envelope(priv, hello)
        await ws.send(json.dumps(hello))
        print("[client] connected. Commands: /list, /tell <user> <text>, /all <text>, /file <user> <path>, /quit")

        async def listener():
            try:
                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        print("[server]", raw)
                        continue

                    t = msg.get("type")

                    if t == "WELCOME":
                        for it in msg.get("users", []):
                            PUBS[it["user"]] = it["pubkey"]
                        print(
                            f"[server] welcome; known users: {sorted(PUBS.keys())}")

                    elif t == "USER_ADDED":
                        PUBS[msg["user"]] = msg["pubkey"]
                        print(f"[server] user added: {msg['user']}")

                    elif t == "PUBKEY_RESPONSE":
                        u = msg.get("user")
                        p = msg.get("pubkey")
                        if u and p:
                            PUBS[u] = p
                            print(f"[server] pubkey cached for {u}")
                        else:
                            print("[server]", msg)

                    elif t == "DM":
                        await handle_dm(priv, msg)

                    elif t == "ALL":
                        print(f"[all] {msg.get('from')}: {msg.get('text')}")

                    elif t == "FILE_START":
                        await handle_file_start(msg)

                    elif t == "FILE_CHUNK":
                        await handle_file_chunk(priv, msg)

                    elif t == "FILE_END":
                        handle_file_end(msg)  # sync; no await

                    elif t == "ERROR":
                        err = (msg.get("error") or "").lower()
                        to_user = msg.get("to") or msg.get(
                            "payload", {}).get("to") or ""
                        nicer = {
                            "user_offline": f"[error] user {to_user or '<unknown>'} is offline",
                            "unknown_user": f"[error] unknown user {to_user or '<unknown>'}",
                            "no_route":     f"[error] no route to user {to_user or '<unknown>'}",
                            "not_found":    "[error] resource not found",
                            "bad_request":  "[error] bad request",
                            "forbidden":    "[error] action not permitted",
                            "internal":     "[error] server encountered an error",
                        }
                        print(
                            nicer.get(err, f"[error] {err or 'unknown error'}"))

                    else:
                        _pretty_server_message(msg, raw)
            except websockets.ConnectionClosed:
                pass

        async def talker():
            loop = asyncio.get_event_loop()
            while True:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break
                line = line.strip()
                if line == "/quit":
                    await ws.close()
                    break
                if line == "/list":
                    req = new_envelope("LIST_REQUEST", user, "server", {})
                    sign_envelope(priv, req)
                    await ws.send(json.dumps(req))
                    continue
                if line.startswith("/tell "):
                    try:
                        _, dest, *rest = line.split()
                        text = " ".join(rest)
                    except Exception:
                        print("usage: /tell <user> <text>")
                        continue
                    dest_pub = PUBS.get(dest)
                    if not dest_pub:
                        # ask server for it; user can retry right after
                        req = new_envelope(
                            "PUBKEY_REQUEST", user, "server", {"user": dest})
                        sign_envelope(priv, req)
                        await ws.send(json.dumps(req))
                        print(
                            f"[client] requested pubkey for {dest}; please retry the command in ~1s")
                        continue
                    dm = build_dm(priv, dest_pub, my_pub_pem, user, dest, text)
                    await ws.send(json.dumps(dm))
                    continue
                if line.startswith("/all "):
                    text = line[len("/all "):].strip()
                    if not text:
                        print("usage: /all <text>")
                        continue
                    # TTL for multi-server forwarding
                    payload = {"text": text, "ttl": 8}
                    env = new_envelope("MSG_BROADCAST", user, "all", payload)
                    sign_envelope(priv, env)
                    await ws.send(json.dumps(env))
                    continue
                if line.startswith("/file "):
                    # /file <user> <path>
                    parts = line.split(maxsplit=2)
                    if len(parts) != 3:
                        print("usage: /file <user> <path>")
                        continue
                    dest, path = parts[1], parts[2]
                    if not os.path.isfile(path):
                        print(f"[file] not found: {path}")
                        continue
                    dest_pub = PUBS.get(dest)
                    if not dest_pub:
                        req = new_envelope(
                            "PUBKEY_REQUEST", user, "server", {"user": dest})
                        sign_envelope(priv, req)
                        await ws.send(json.dumps(req))
                        print(
                            f"[client] requested pubkey for {dest}; retry /file once cached")
                        continue
                    await send_file(ws, priv, my_pub_pem, user, dest, dest_pub, path)
                    continue
                print(
                    "[client] unknown command. Try: /list, /tell, /all, /file, /quit")

        await asyncio.gather(listener(), talker())


# DM handling
async def handle_dm(priv, msg):
    payload = msg.get("payload", {})
    ct_b64 = payload.get("ciphertext")
    csig_b64 = payload.get("content_sig")
    sender = msg.get("from")
    dest = msg.get("to")
    ts = msg.get("ts")

    if ct_b64 and csig_b64 and sender and dest and ts is not None:
        # fallback to sender_pub in payload for cross-server first contact
        spem = PUBS.get(sender) or payload.get("sender_pub")
        if not spem:
            print(f"[dm] {sender}: <no sender pubkey cached>")
            return
        if sender not in PUBS:
            PUBS[sender] = spem
        try:
            spub = load_public_key(spem)
            signed_bytes = (
                b64u_decode(ct_b64)
                + str(sender).encode()
                + str(dest).encode()
                + str(ts).encode()
            )
            ok = verify_pss(spub, signed_bytes, b64u_decode(csig_b64))
            if not ok:
                print(f"[dm] {sender}: <bad content signature>")
                return
        except Exception as e:
            print(f"[dm] {sender}: <sig verify error> ({e})")
            return

        try:
            plaintext = rsa_oaep_decrypt(
                priv, b64u_decode(ct_b64)).decode("utf-8", "replace")
            print(f"[dm] {sender}: {plaintext}")
        except Exception as e:
            print(f"[dm] {sender}: <cannot decrypt> ({e})")
    else:
        print("[server]", json.dumps(msg))


# File send
async def send_file(ws, priv, my_pub_pem, me, dest, dest_pub_pem, path):
    size = os.path.getsize(path)
    name = os.path.basename(path)
    sha = sha256_file(path)
    total = (size + CHUNK_SIZE - 1) // CHUNK_SIZE
    file_id = f"{name}-{sha[:16]}"

    if size > MAX_SIZE or total > MAX_CHUNKS:
        print("[file] too large, rejecting")
        return

    # FILE_START (manifest)
    start_payload = {
        "file_id": file_id,
        "name": name,
        "size": size,
        "sha256": sha,
        "total_chunks": total,
        "sender_pub": my_pub_pem,
    }
    start_env = new_envelope("FILE_START", me, dest, start_payload)
    sign_envelope(priv, start_env)
    await ws.send(json.dumps(start_env))
    print(f"[file] start -> {dest}: {name} ({size} bytes, {total} chunks)")

    # brief pause helps overlay during peer reconnects / adverts
    await asyncio.sleep(0.5)

    # Send chunks (RSA-OAEP; plaintext <= ~446 bytes; we use CHUNK_SIZE=400)
    rpub = load_public_key(dest_pub_pem)
    with open(path, "rb") as f:
        idx = 0
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            ct = rsa_oaep_encrypt(rpub, chunk)

            # 1) build payload WITHOUT content_sig
            ch_payload = {
                "file_id": file_id,
                "idx": idx,
                "ciphertext": b64u(ct),
                "sender_pub": my_pub_pem,
            }

            # 2) create the envelope to get its ts
            ch_env = new_envelope("FILE_CHUNK", me, dest, ch_payload)

            # 3) compute content signature bound to (ct, me, dest, ts, file_id, idx)
            ts = ch_env["ts"]
            signed = b"".join([
                ct,
                me.encode(),
                dest.encode(),
                str(ts).encode(),
                file_id.encode(),
                str(idx).encode()
            ])
            csig = sign_pss(priv, signed)

            # 4) inject content_sig into payload
            ch_env["payload"]["content_sig"] = b64u(csig)

            # 5) re-sign the transport envelope (payload changed)
            sign_envelope(priv, ch_env)

            print(f"[file] send chunk {idx+1}/{total} -> {dest}")
            await asyncio.sleep(0.05)
            await ws.send(json.dumps(ch_env))
            idx += 1

    # FILE_END (binds to total count)
    end_payload = {"file_id": file_id, "total_chunks": total}
    end_env = new_envelope("FILE_END", me, dest, end_payload)
    sign_envelope(priv, end_env)
    await ws.send(json.dumps(end_env))
    print(f"[file] end -> {dest}: {name}")


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(128 * 1024), b""):
            h.update(b)
    return h.hexdigest()


# File receive
async def handle_file_start(msg):
    """
    Handle FILE_START (manifest). Creates RX entry but doesn't write to disk yet.
    """
    payload = msg.get("payload", {})
    file_id = payload.get("file_id")
    name = payload.get("name")
    size = int(payload.get("size", 0))
    sha = payload.get("sha256", "")
    total = int(payload.get("total_chunks", 0))

    if not file_id or not name or not total:
        print("[file] bad FILE_START")
        return

    # Sanitize filename and enforce size caps
    name = os.path.basename(name)
    if not name or any(c in name for c in ["..", "/", "\\"]):
        print("[file] invalid filename, rejecting")
        return
    if size > MAX_SIZE or total > MAX_CHUNKS:
        print("[file] too large, rejecting")
        return

    # Ignore duplicates for same transfer (retry-friendly)
    if file_id in RX:
        return

    os.makedirs("downloads", exist_ok=True)
    RX[file_id] = {"name": name, "size": size, "sha256": sha,
                   "total": total, "got": 0, "chunks": {}}
    print(
        f"[file] start <- {msg.get('from')}: {name} ({size} bytes, {total} chunks)")


async def handle_file_chunk(priv, msg):
    """
    Handle FILE_CHUNK. Verifies sender’s content signature, decrypts chunk,
    stores it in RX[file_id]['chunks'][idx].
    """
    payload = msg.get("payload", {})
    file_id = payload.get("file_id")
    idx = payload.get("idx")
    ct_b64 = payload.get("ciphertext")
    csig_b64 = payload.get("content_sig")
    sender = msg.get("from")
    dest = msg.get("to")
    ts = msg.get("ts")

    if file_id not in RX or idx is None or not ct_b64 or not csig_b64:
        print("[file] bad FILE_CHUNK")
        return

    # Verify sender key (fallback to sender_pub carried in the payload for first contact)
    spem = PUBS.get(sender) or payload.get("sender_pub")
    if not spem:
        print(f"[file] {sender}: <no sender pubkey cached>")
        return
    if sender not in PUBS:
        PUBS[sender] = spem

    # Verify content signature binds: ciphertext + addressing + ts + file_id + idx
    try:
        spub = load_public_key(spem)
        signed_bytes = (
            b64u_decode(ct_b64)
            + str(sender).encode()
            + str(dest).encode()
            + str(ts).encode()
            + str(file_id).encode()
            + str(idx).encode()
        )
        ok = verify_pss(spub, signed_bytes, b64u_decode(csig_b64))
        if not ok:
            print(f"[file] {sender}: <bad chunk signature idx={idx}>")
            return
    except Exception as e:
        print(f"[file] {sender}: <sig verify error idx={idx}> ({e})")
        return

    # Decrypt RSA-OAEP chunk (must be <= ~446 bytes plaintext for 4096-bit key / SHA-256 OAEP)
    try:
        pt = rsa_oaep_decrypt(priv, b64u_decode(ct_b64))
    except Exception as e:
        print(f"[file] {sender}: <cannot decrypt chunk idx={idx}> ({e})")
        return

    # Store decrypted plaintext by index
    RX[file_id]["chunks"][int(idx)] = pt
    RX[file_id]["got"] = len(RX[file_id]["chunks"])
    print(
        f"[file] got chunk {int(idx)+1}/{RX[file_id]['total']} for {RX[file_id]['name']}")
    if RX[file_id]["got"] % 10 == 0 or RX[file_id]["got"] == RX[file_id]["total"]:
        print(
            f"[file] recv {RX[file_id]['got']}/{RX[file_id]['total']} chunks for {RX[file_id]['name']}")


def handle_file_end(msg):
    """
    Handle FILE_END. Writes the file only if all chunks are present and checksum matches (if provided).
    Prevents writing empty/partial files.
    """
    payload = msg.get("payload", {})
    file_id = payload.get("file_id")
    total = int(payload.get("total_chunks", 0))
    info = RX.get(file_id)

    if not info:
        print("[file] bad FILE_END (unknown file_id)")
        return

    got = len(info["chunks"])
    if got != total or total != info["total"]:
        print(f"[file] missing chunks: got {got}/{total} — not saving")
        return

    out_name = info["name"]
    out_path = _unique_download_path(out_name)

    # Reassemble in order
    with open(out_path, "wb") as out:
        for i in range(info["total"]):
            if i not in info["chunks"]:
                print(f"[file] missing chunk {i}, aborting")
                return
            out.write(info["chunks"][i])

    # Verify checksum if provided
    if info["sha256"]:
        h = hashlib.sha256()
        with open(out_path, "rb") as f:
            for b in iter(lambda: f.read(128 * 1024), b""):
                h.update(b)
        got_sha = h.hexdigest()
        if got_sha != info["sha256"]:
            print(
                f"[file] SHA256 mismatch! expected {info['sha256']} got {got_sha}")
            return

    print(f"[file] saved to {out_path}")
    RX.pop(file_id, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="ws://host:port")
    ap.add_argument("--user", required=True)
    args = ap.parse_args()
    asyncio.run(run(args.server, args.user))


if __name__ == "__main__":
    main()

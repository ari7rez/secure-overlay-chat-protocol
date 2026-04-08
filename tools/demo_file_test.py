import asyncio
import os
import subprocess
import sys
import time

PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TESTFILE = os.path.join(PROJECT, "test_file.txt")
DOWNLOADS = os.path.join(PROJECT, "downloads", "test_file.txt")


async def main():
    # Create a test file
    with open(TESTFILE, "w") as f:
        f.write("hello from alice\n")

    print("[demo] starting server...")
    srv = subprocess.Popen(
        ["python3", "-m", "src.server.server", "--id", "SrvA",
            "--port", "9001", "--bootstrap", "config/bootstrap.yaml"],
        cwd=PROJECT,
    )
    time.sleep(1)

    print("[demo] starting Bob client...")
    bob = subprocess.Popen(
        ["python3", "-m", "src.client.cli", "--server",
            "ws://127.0.0.1:9001", "--user", "bob"],
        cwd=PROJECT,
        stdin=subprocess.PIPE,
        text=True,
    )
    time.sleep(1)

    print("[demo] starting Alice client...")
    alice = subprocess.Popen(
        ["python3", "-m", "src.client.cli", "--server",
            "ws://127.0.0.1:9001", "--user", "alice"],
        cwd=PROJECT,
        stdin=subprocess.PIPE,
        text=True,
    )
    time.sleep(2)

    print("[demo] sending file from Alice -> Bob...")
    alice.stdin.write(f"/file bob {TESTFILE}\n")
    alice.stdin.flush()

    # wait up to 5s for Bob to receive
    for _ in range(10):
        if os.path.exists(DOWNLOADS):
            print("[demo] file arrived at Bob’s downloads!")
            with open(DOWNLOADS) as f:
                print("[demo] content:", f.read().strip())
            break
        time.sleep(0.5)
    else:
        print("[demo] file not found in Bob’s downloads")

    # clean up
    alice.kill()
    bob.kill()
    srv.kill()

if __name__ == "__main__":
    asyncio.run(main())

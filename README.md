# SOCP v1.3 — Secure Overlay Chat Protocol

A secure, encrypted **overlay chat and file transfer system** implemented in Python.  
Built as part of the *Advanced Secure Programming* assignment, it demonstrates protocol design, secure coding practices and multi-server federation.

---

## ✨ Features

- ✅ Direct messages (DM) with RSA-OAEP encryption + PSS signatures  
- ✅ Broadcast messages (`/all`) with TTL for multi-server forwarding  
- ✅ File transfer (chunked, encrypted, verified by SHA-256)  
- ✅ Multi-server federation via gossip + bootstrap config  
- ✅ SQLite-backed user/session database  
- ✅ Logging with configurable `--log-level` and optional `--log-file`  
- ✅ Security limits (50 MB max file, 8192 chunks, filename sanitization)  

---

## ⚙️ Setup

### 1. Clone and enter project
```bash
git clone https://github.com/yourname/socp.git
cd socp
```

### 2. Create and activate venv
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

---

## 🚀 Running Servers & Clients

### Run 2 servers (two terminals)
```bash
PYTHONPATH=$(pwd) python3 -m src.server.server --id SrvA --port 9001 --bootstrap config/bootstrap_A.yaml
PYTHONPATH=$(pwd) python3 -m src.server.server --id SrvB --port 9002 --bootstrap config/bootstrap_B.yaml
```

### Run clients (two more terminals)
```bash
PYTHONPATH=$(pwd) python3 -m src.client.cli --server ws://127.0.0.1:9001 --user "anyname"
PYTHONPATH=$(pwd) python3 -m src.client.cli --server ws://127.0.0.1:9002 --user "anyname"
```

---

## 💬 Commands

Inside client terminal:

```
/list                          # list users
/tell <user> <text>            # direct message
/all <text>                    # broadcast to all servers
/file <user> <path>            # send file
/quit                          # exit
```

---

## 📁 File Transfer

- Files are split into chunks (`CHUNK_SIZE=400` bytes for RSA safety).  
- Each chunk is encrypted with RSA-OAEP and signed with RSA-PSS.  
- Receiver reassembles chunks and validates SHA-256 checksum.  
- Files are saved to `downloads/`.

---

## 🧪 Demo Test Script

We provide `tools/demo_file_test.py` to automate a test transfer.

### Run demo
```bash
# Stop other servers first (Ctrl+C or kill process on :9001)
lsof -i :9001
kill -9 <PID>

# Run demo
PYTHONPATH=$(pwd) python tools/demo_file_test.py
```

Expected output:
```
[demo] file arrived at Bob’s downloads!
[demo] content: hello from alice
```

---

## 🛠 Troubleshooting

- **Address already in use**  
  Kill process holding the port:  
  ```bash
  lsof -i :9001
  kill -9 <PID>
  ```

- **File not saved**  
  - Ensure both servers are running.  
  - Retry `/file` once (peer adverts may take a second).  
  - Check `downloads/` folder.  

- **pip broken**  
  Recreate virtualenv:  
  ```bash
  deactivate
  rm -rf .venv
  python3 -m venv .venv --upgrade-deps
  source .venv/bin/activate
  python -m pip install -r requirements.txt
  ```

---

## 🔒 Security Notes

- All DM and file chunks use **RSA-OAEP** encryption and **RSA-PSS** signatures.  
- Broadcast uses TTL to avoid flooding loops.  
- Limits applied: 50 MB per file, 8192 chunks.  
- Filenames sanitized before saving.  

---

## 🚪 Backdoors 

- 2 intentional backdoors have been added for analysis
- Backdoors demonstrate real-world vulnerability patterns
- Designed to maintain system functionality while providing covert access

---

## 📞 Contact

- Project Team:

1. Mohammad Ali Rezaei
- Email: mohammadali.rezaei@student.adelaide.edu.au

2. Sahaj Pal Singh Mahla
- Email: sahajpalsingh.mahla@student.adelaide.edu.au

3. Gotam Raj
- Email: gotam.raj@student.adelaide.edu.au

--- 

## 📜 License

MIT License — see `LICENSE` file.

---
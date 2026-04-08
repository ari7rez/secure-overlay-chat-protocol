# Secure Overlay Chat Protocol (SOCP)

## Overview
A secure messaging and file transfer system implemented in Python.  
This project demonstrates protocol design, cryptographic security, and distributed communication across multiple servers.

## Key Highlights
- Designed a secure messaging protocol from scratch
- Implemented cryptographic primitives in a real system
- Built a distributed multi-server communication model

---

## Features
- End-to-end encrypted direct messaging (RSA-OAEP)
- Digital signatures using RSA-PSS
- Broadcast messaging with TTL for multi-server propagation
- Secure file transfer with SHA-256 integrity verification
- Multi-server federation using gossip-based communication
- SQLite-backed user and session management
- Configurable logging and runtime options

---

## Tech Stack
- Python
- Cryptography (RSA-OAEP, RSA-PSS, SHA-256)
- SQLite
- WebSocket-based communication

---

## Security Features
- Encryption: RSA-OAEP
- Authentication: RSA-PSS signatures
- Integrity: SHA-256 hashing
- Input validation and filename sanitization
- Controlled file transfer limits

---

## System Architecture
The system operates as a distributed overlay network:
- Multiple servers communicate via gossip protocol
- Clients connect to servers and exchange encrypted messages
- Messages and files propagate securely across nodes

---

## How to Run

### Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Start Servers

PYTHONPATH=$(pwd) python3 -m src.server.server --id SrvA --port 9001 --bootstrap config/bootstrap_A.yaml
PYTHONPATH=$(pwd) python3 -m src.server.server --id SrvB --port 9002 --bootstrap config/bootstrap_B.yaml

Start Clients

PYTHONPATH=$(pwd) python3 -m src.client.cli --server ws://127.0.0.1:9001 --user user1
PYTHONPATH=$(pwd) python3 -m src.client.cli --server ws://127.0.0.1:9002 --user user2


⸻

Commands

/list                          # list users
/tell <user> <text>            # direct message
/all <text>                    # broadcast message
/file <user> <path>            # send file
/quit                          # exit


⸻

My Contribution
	•	Designed and implemented secure messaging protocol
	•	Developed encryption and digital signature workflow
	•	Built secure file transfer with integrity verification
	•	Implemented multi-server communication and message propagation
	•	Applied secure coding practices and input validation

⸻

Project Context

Originally developed as part of a secure programming project and refined here as a portfolio implementation of a secure distributed communication system.

⸻

Repository Structure

src/        # core implementation
config/     # server configuration
tools/      # testing utilities
data/       # runtime storage (ignored in Git)


⸻

Notes

This repository represents a cleaned and portfolio-ready version of the original team project, focusing on secure system design and implementation.

⸻

License

MIT License

---

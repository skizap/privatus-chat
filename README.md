# Privatus-chat

A decentralized, end-to-end encrypted chat application that prioritizes **privacy**, **anonymity**, and **cross-platform usability**. The project is now feature-complete (10 / 10 development phases) and ready for production deployment and open-source collaboration.

---

## ✨ Key Features

- **Signal-Protocol Messaging** (X3DH + Double Ratchet) for perfect forward secrecy
- **Onion-Routed Networking** with traffic-analysis resistance
- **Voice Calls & File Transfer** over the same anonymized tunnels
- **Group Chat** with shared symmetric session keys
- **Cross-Platform GUI** (PyQt6) for Windows, macOS, and Linux
- **Secure Auto-Updater** with cryptographic release verification
- **Performance Suite** (crypto, memory, network optimizers) and live metrics
- **Security Toolkit** (static auditor, protocol fuzzer, vulnerability scanner)
- **Fully Encrypted Local Storage** (SQLCipher3)

---

## 🗺️ Repository Overview

| Path                  | Purpose                                                |
|-----------------------|--------------------------------------------------------|
| `src/`                | Application source code (runtime packages)             |
| `deployment/`         | Packaging, auto-update, and platform-integration tools |
| `docs/`               | User & developer documentation (Markdown)             |
| `examples/`           | Demonstration scripts for major subsystems            |
| `tests/`              | Pytest suites for crypto, networking, anonymity       |
| `config/`             | Environment configuration files                        |

---

## 🏗️ Architecture Snapshot

1. **GUI** (`src.gui`) → captures user actions
2. **Messaging** (`src.messaging`) → encrypts & routes messages
3. **Crypto** (`src.crypto`) → Double Ratchet / group keys
4. **Anonymity** (`src.anonymity`) → onion wrapping & privacy controls
5. **Network** (`src.network`) → P2P transport via Kademlia DHT & NAT traversal
6. **Cross-Cutting** → performance monitors & security auditors

> For an in-depth explanation, see [`docs/developer/architecture.md`](https://github.com/skizap/privatus-chat/blob/main/docs/developer/architecture.md).

---

## 🚀 Quick Start (End Users)

```bash
# 1. Clone and enter the project
$ git clone https://github.com/skizap/privatus-chat.git
$ cd privatus-chat

# 2. Create & activate a Python 3.11+ virtual environment
$ python -m venv venv
$ source venv/bin/activate        # (Windows) venv\Scripts\activate

# 3. Install runtime dependencies
(venv) $ pip install -r requirements.txt

# 4. Launch the GUI
(venv) $ python launch_gui.py
```

---

## 👩‍💻 Development Workflow

```bash
# Install dev dependencies
(venv) $ pip install -r requirements-dev.txt

# Run unit tests with coverage
(venv) $ pytest -ra --cov=src --cov-report=term-missing

# Static type-checking & linting
(venv) $ mypy src/
(venv) $ pylint src/

# Build a standalone desktop package
(venv) $ python deployment/deploy.py --platform auto --sign
```

---

## 🧪 Demonstrations

| Demo Script                       | Description                              |
|-----------------------------------|------------------------------------------|
| `examples/comprehensive_demo.py`  | Full end-to-end feature showcase         |
| `examples/gui_demo.py`            | GUI-only walkthrough (no network)        |
| `examples/week5_gui_demo.py`      | Stand-alone UI enhancements              |
| `examples/phase9_security_demo.py`| Security auditing & fuzzing pipeline     |

Run any demo with `python examples/<script>.py`.

---

## 🔒 Security Notice

Privatus-chat implements state-of-the-art protocols and has undergone automated static and dynamic analysis. Nevertheless, **no software can be considered perfectly secure**. We welcome independent audits and responsible vulnerability disclosures (see [`SECURITY.md`](https://github.com/skizap/privatus-chat/blob/main/SECURITY.md)).

---

## 🤝 Contributing

1. Fork [https://github.com/skizap/privatus-chat](https://github.com/skizap/privatus-chat) → create a feature branch → open a pull request.
2. Follow the **security-first** development checklist in [`CONTRIBUTING.md`](https://github.com/skizap/privatus-chat/blob/main/CONTRIBUTING.md).
3. New features must include tests and updated documentation.
4. All cryptographic or networking code changes require peer review.

---

## 📄 License

This project is licensed under the **MIT License**. See [`LICENSE`](https://github.com/skizap/privatus-chat/blob/main/LICENSE) for details.

---

## 📞 Contact

For questions, bug reports, or security disclosures, please [open an issue](https://github.com/skizap/privatus-chat/issues) on GitHub.

---

**Built with privacy and security at its core.** 🔐 
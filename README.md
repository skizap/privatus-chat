# Privatus-chat

A decentralized, end-to-end encrypted chat application that prioritizes **privacy**, **anonymity**, and **cross-platform usability**. The project is now feature-complete (10 / 10 development phases) and ready for production deployment and open-source collaboration.

---

## ✨ Key Features

- **Signal-Protocol Messaging** (X3DH + Double Ratchet) for perfect forward secrecy
- **Onion-Routed Networking** with traffic-analysis resistance
- **Advanced Voice Calls** with multiple quality levels, voice privacy protection, and adaptive quality
- **Secure File Transfer** with chunked large file support, resume/pause, and integrity verification
- **Group Chat** with shared symmetric session keys
- **Cross-Platform GUI** (PyQt6) for Windows, macOS, and Linux
- **Secure Auto-Updater** with cryptographic release verification
- **Performance Monitoring** with real-time metrics, benchmarking suite, and automatic optimization
- **Security Testing Framework** with automated auditing, vulnerability scanning, and compliance reporting
- **Fully Encrypted Local Storage** (SQLCipher3)

---

## 🗺️ Repository Overview

| Path                  | Purpose                                                |
|-----------------------|--------------------------------------------------------|
| `src/`                | Application source code (runtime packages)             |
| `deployment/`         | Packaging, auto-update, and platform-integration tools |
| `docs/`               | User & developer documentation (Markdown)             |
| `docs/user/`          | User guides, FAQs, installation, and best practices    |
| `docs/developer/`     | Developer guides, API reference, and architecture      |
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

## 📚 Documentation

| Documentation | Description |
|---------------|-------------|
| **[User Guide](docs/user/user-guide.md)** | Complete guide to using Privatus-chat features |
| **[Installation Guide](docs/user/installation-guide.md)** | Platform-specific installation instructions |
| **[FAQ](docs/user/faq.md)** | Frequently asked questions and answers |
| **[Security Best Practices](docs/user/security-best-practices.md)** | Essential security guidelines |
| **[Voice Communication](docs/user/feature-voice-communication.md)** | Advanced voice calling features |
| **[File Transfer](docs/user/feature-file-transfer.md)** | Secure file sharing capabilities |
| **[Performance Monitoring](docs/user/feature-performance-monitoring.md)** | System optimization and monitoring |
| **[Security Testing](docs/user/feature-security-testing.md)** | Vulnerability scanning and auditing |
| **[Developer Guide](docs/developer/developer-guide.md)** | Contributing and extending Privatus-chat |
| **[API Reference](docs/developer/api-reference.md)** | Complete API documentation |

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
| `examples/phase8_performance_demo.py` | Performance monitoring & optimization  |
| `examples/phase9_security_demo.py`| Security auditing & vulnerability scanning|
| `examples/phase10_documentation_demo.py` | Documentation generation & validation |

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

---

## 🆕 Latest Updates (January 2025)

### Enhanced Voice Communication
- **Multiple quality levels** (Ultra, High, Medium, Low) with automatic adaptation
- **Advanced audio processing** with echo cancellation and noise reduction
- **Voice privacy protection** including fingerprint obfuscation
- **Real-time call statistics** and performance monitoring

### Secure File Transfer System
- **Chunked large file support** with resume/pause capabilities
- **Integrity verification** using SHA-256 checksums
- **Anonymous routing** through onion circuits
- **Metadata protection** and automatic scrubbing

### Performance Monitoring Suite
- **Real-time metrics collection** for system and application performance
- **Comprehensive benchmarking** for crypto, network, and memory operations
- **Automatic optimization** with adaptive algorithms
- **Performance dashboard** with historical trends and alerts

### Security Testing Framework
- **Automated vulnerability scanning** with pattern-based detection
- **Cryptographic analysis** and compliance verification
- **Security audit reporting** in multiple formats (JSON, HTML, PDF)
- **Continuous monitoring** with real-time alerts

### Documentation Updates
- **Comprehensive feature documentation** for all major systems
- **Updated user guides** with latest features and best practices
- **Enhanced API reference** with new capabilities
- **Security best practices** reflecting current threat landscape
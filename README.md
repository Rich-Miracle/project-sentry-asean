# 🛡️ Project Sentry ASEAN

**A content-aware, PDPA-compliant outbound data-loss prevention system for enterprise egress traffic.**

Project Sentry ASEAN inspects an organisation's outbound network traffic — including encrypted email and file uploads — and enforces Singapore's *Personal Data Protection Act (PDPA) Transfer Limitation Obligation* on the actual content leaving the network, rather than on destination IP addresses alone.

The system decrypts TLS in transit using an organisation-controlled certificate authority, extracts and inspects the payload (plaintext, PDF, DOCX, and text-bearing images via OCR), detects personal data, and reasons about whether the transfer is lawful under the PDPA using a retrieval-augmented local language model grounded in a curated legal corpus.

> 🎓 Final Year Project — Asia Pacific University (APU). This repository accompanies the project dissertation.

---

## 🤔 Why this exists

Conventional egress firewalls decide whether to permit a transfer based on *where* it is going — the destination IP or domain. That approach cannot answer the question the PDPA actually asks: *does this specific transfer move personal data to a jurisdiction without comparable protection, absent a documented safeguard?*

A destination-based rule blocks a harmless message to a flagged country and permits a customer database dumped to an "allowed" one. Project Sentry ASEAN moves the decision to the **content**: it reads what is actually being sent, identifies personal data, and applies the transfer rules to that data.

---

## ✨ Core capabilities

- 🔓 **Transparent TLS interception** — SMTPS (email) and HTTPS (file upload) are decrypted in transit via `iptables` redirection into a transparent proxy, so an application cannot opt out of inspection.
- 🔍 **Content-aware PII detection** — Microsoft Presidio with custom Singapore recognisers (NRIC, local phone formats), plus an OCR-aware NRIC recogniser that recovers misread characters from scanned identity cards by validating candidates against the NRIC checksum.
- 📄 **Multi-format extraction** — plaintext, PDF, and DOCX extraction, plus OCR for text-bearing images. File type is determined by **magic-byte sniffing**, not the sender's declared MIME type, closing a content-type evasion vector.
- ⚖️ **Grounded legal reasoning** — a local language model (via Ollama) reasons about each transfer using retrieval-augmented generation over a curated PDPA corpus, and cites the specific clause supporting each verdict.
- 🌏 **Safeguard-aware verdicts** — a transfer to a non-equivalent jurisdiction is permitted when a documented safeguard (e.g. the ASEAN Model Contractual Clauses) is on file, and blocked when none exists — the distinction the PDPA actually draws.
- 🚫 **Enforcement before commit** — a blocked email never reaches the mail server: the interception layer withholds the SMTP data terminator so the message is never queued.
- 🧾 **Audit reporting** — every enforcement action produces a PDF audit report with detected entities, Presidio confidence scores, sensitivity classification, and the cited PDPA clause.
- 📊 **Observability** — Prometheus metrics and Grafana dashboards, with aggregated logs from all inspection paths via Loki.

---

## 🏗️ Architecture

The system is organised into three conceptual planes:

| Plane | Role | Components |
|-------|------|-----------|
| 🛡️ **Enforcement** | Intercepts and acts on traffic | eBPF TCX-egress program, transparent proxy (mitmproxy), `iptables` redirection |
| 🔬 **Inspection** | Extracts and understands content | extraction router, Presidio detectors, OCR |
| 🧠 **Decision** | Reasons about lawfulness | RAG engine, local LLM, PDPA corpus |

All inspection paths converge on a single evaluation endpoint (`/evaluate`), which returns a deterministic verdict (the block/allow decision) accompanied by an LLM-generated justification and clause citation. The decision is auditable and rule-grounded; the language model supplies the *reasoning and legal citation*, not the verdict itself.

### ⚡ Trap-and-Evaluate model

The eBPF program attaches at **TCX egress** (`AttachTCX`, the modern kernel attachment API) and keys each flow against a kernel-resident verdict map. A flow with a cached verdict is enforced in-kernel; a flow with no cached verdict is trapped, and its leading payload bytes (up to a 4096-byte capture bound) are surfaced to userspace over a ring buffer for evaluation. The controller writes the resulting verdict back into the kernel map. Destinations the system cannot evaluate are dropped, not allowed (fail-secure).

### 🔀 Why two enforcement mechanisms

The eBPF and proxy planes are complementary, not redundant. At egress the eBPF program sees traffic **after** TLS encryption, so it can enforce a cached verdict at kernel speed but cannot read encrypted content. Content inspection therefore happens in the **proxy plane**, which terminates TLS with the organisation's own certificate authority and reads the decrypted payload. In short: the proxy plane *understands* traffic, the eBPF plane *enforces* judgements at kernel speed once they exist.

---

## 🧰 Technology stack

**🛡️ Enforcement & networking:** eBPF (libbpf CO-RE, clang/LLVM), Go controller, mitmproxy (transparent mode), Postfix, iptables

**🤖 Inspection & AI:** Python, FastAPI, Microsoft Presidio, Tesseract OCR, sentence-transformers (MiniLM), ChromaDB, Ollama (local LLM)

**📊 Observability:** Prometheus, Grafana, Loki, Promtail

**🖥️ Interface:** React (demonstration console), ReportLab (PDF audit reports)

**📦 Orchestration:** Docker Compose

---

## 📁 Repository layout

```
agent/          Python AI agent — PII detection, extraction routing, RAG engine, audit reports
  corpus/       Curated PDPA legal corpus (tagged clauses)
controller/     Go controller — eBPF loader, flow reassembler, jurisdiction resolution
kernel/         eBPF TCX-egress program (C)
compose/        Docker Compose stack, per-service Dockerfiles, jurisdiction mapping
demo-ui/        "Meridian Mail" demonstration console (React, Flask-served)
monitoring/     Prometheus, Grafana, and Loki configuration
tests/          Fixtures and test harness
sentry.sh       Administrator control console (start/stop, health, demo, logs, corpus review)
start.sh        Stack startup with service readiness gates
setup-transparent.sh   Transparent interception setup (iptables, proxies, upload target)
```

---

## 🚀 Running the system

> ⚙️ Requires Docker and Docker Compose on a Linux host. Developed and tested on Ubuntu.

```bash
# Start the full stack and configure transparent interception
./sentry.sh          # option 1 — start

# Or manually:
./start.sh
./setup-transparent.sh
```

The administrator console (`sentry.sh`) provides start/stop, component health, a live demonstration of both interception paths, audit report access, live log viewing, and review of the PDPA knowledge base the reasoning engine consults.

🌐 The demonstration console is served at `http://<host>:8090` — compose an email or upload a file to a chosen destination and observe the enforcement verdict.

---

## 🎬 Demonstration

Sending the same personal data (a Singapore NRIC) to three destinations demonstrates the content-aware, safeguard-aware behaviour:

| Destination | Verdict | Basis |
|-------------|---------|-------|
| 🇸🇬 **Singapore** | ✅ Permitted | Domestic — the Transfer Limitation Obligation is not engaged |
| 🇲🇾 **Malaysia** | ✅ Permitted | Non-equivalent jurisdiction, but a documented ASEAN MCC safeguard applies |
| 🇺🇸 **United States** | ⛔ Blocked | Non-equivalent jurisdiction with no documented safeguard |

The same data, three different lawful outcomes, decided by content and safeguard rather than destination alone.

---

## ⚠️ Scope and limitations

This is a research proof of concept. Notable boundaries, documented in full in the dissertation:

- Enforcement covers technically verifiable transfer conditions; it does not adjudicate consent or business purpose.
- The language model's decision role is deliberately narrow and bounded by deterministic rules; it supplies justification and citation, not the verdict.
- User-to-user communication is out of scope; the system inspects company-internal outbound traffic.
- Certificate-pinned services (e.g. major cloud providers) cannot be intercepted — a known limitation of any TLS-terminating inspection approach.
- Bare face detection and audio/voice content are out of scope.

---

## 🙏 Acknowledgements

Built as a Final Year Project at Asia Pacific University. The PDPA corpus draws on the Personal Data Protection Act 2012, the Personal Data Protection Regulations 2021, and PDPC guidance, including the ASEAN Model Contractual Clauses and the Global CBPR framework.

---

*📚 This repository is academic coursework and is not intended for production deployment without substantial hardening.*

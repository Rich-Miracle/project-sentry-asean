FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# --- System packages ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping netcat-openbsd tcpdump curl \
    clang llvm libbpf-dev linux-tools-generic \
    build-essential pkg-config \
    python3 python3-venv python3-pip \
    poppler-utils tesseract-ocr \
    ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*

# --- Go (for the controller) ---
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz \
    && rm go1.22.0.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# --- Python agent environment ---
WORKDIR /agent
RUN python3 -m venv /agent/.venv
ENV PATH="/agent/.venv/bin:${PATH}"

# Install Python deps into the venv (layer cached unless this list changes)
RUN /agent/.venv/bin/pip install --no-cache-dir --upgrade pip && \
    /agent/.venv/bin/pip install --no-cache-dir \
        presidio-analyzer click \
        pdfminer.six python-docx pytesseract Pillow pdf2image reportlab \
        pytest requests \
        fastapi uvicorn pydantic \
        pytest requests mitmproxy \
        google-genai chromadb sentence-transformers langchain langchain-community

RUN /agent/.venv/bin/pip install --no-cache-dir prometheus-client

# passlib/bcrypt incompatibility — mitmproxy fails to import with bcrypt >= 4.1
RUN /agent/.venv/bin/pip install --no-cache-dir "bcrypt<4.1"

# spaCy model (large download, separate layer so it caches)
RUN /agent/.venv/bin/python -m spacy download en_core_web_lg

# --- Copy agent source in ---
COPY agent/ /agent/
COPY controller/ /controller/
COPY kernel/tc_hook.o /controller/tc_hook.o
COPY compose/jurisdiction.yaml /controller/jurisdiction.yaml
COPY demo-ui/demo_server.py /agent/demo_server.py
COPY demo-ui/index.html /agent/index.html

# --- Build the Go controller at image-build time ---
WORKDIR /controller
RUN /usr/local/go/bin/go build -o sentry-controller .

WORKDIR /agent

# Transparent-proxy user + CA confdir (for mitmproxy SO_ORIGINAL_DST interception)
RUN useradd -r -s /bin/false mitmuser
COPY compose/mitm-ca/ /home/mitmuser/.mitmproxy/
RUN chown -R mitmuser /home/mitmuser/.mitmproxy

CMD ["sleep", "infinity"]

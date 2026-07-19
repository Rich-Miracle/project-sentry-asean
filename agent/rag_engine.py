"""
Subsystem 4d — RAG Legal Reasoning Engine for Project Sentry ASEAN.

Pipeline:
  1. Load PDPA corpus, split into tagged chunks.
  2. Embed with all-MiniLM-L6-v2, store in ChromaDB (in-memory).
  3. Retrieve top-k relevant clauses for a query.
  4. Gemini reasons over retrieved clauses -> JSON verdict.
  5. Verify the cited clause tag actually exists in the corpus (anti-hallucination).
"""

import os
import re
import json
import logging
import time
import threading

import requests
import chromadb
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)

CORPUS_PATH = "/agent/corpus/pdpa_transfer_limitation.txt"
EMBED_MODEL = "all-MiniLM-L6-v2"
TOP_K = 2

# Backend selection: "ollama" (local, default) or "gemini" (external fallback).
LLM_BACKEND = os.environ.get("LLM_BACKEND", "ollama").lower()

# Completed justifications, keyed by flow_id. Populated asynchronously.
justification_store = {}

# Ollama (local) config.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://172.30.0.50:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

# Gemini (external) config — used only if LLM_BACKEND=gemini.
GEMINI_MODEL = "gemini-3-flash-preview"

# Matches chunk tags like [PDPA-S26-1] at the start of a chunk.
_TAG_RE = re.compile(r"\[([A-Z0-9\-]+)\]")


class RagEngine:
    def __init__(self, corpus_path: str = CORPUS_PATH):
        self.corpus_path = corpus_path
        self.chunks = {}          # tag -> full chunk text
        self._init_chroma()
        self._load_corpus()
        self._init_llm()

    # --- setup ---

    def _init_chroma(self):
        self.client = chromadb.Client()
        self.embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBED_MODEL
        )
        # Fresh collection each run (in-memory PoC).
        try:
            self.client.delete_collection("pdpa")
        except Exception:
            pass
        self.collection = self.client.create_collection(
            name="pdpa", embedding_function=self.embed_fn
        )

    def _load_corpus(self):
        with open(self.corpus_path, "r", encoding="utf-8") as f:
            raw = f.read()

        # Split on blank lines; each block is one tagged chunk.
        blocks = [b.strip() for b in raw.split("\n\n") if b.strip()]
        ids, docs = [], []
        for block in blocks:
            m = _TAG_RE.search(block)
            if not m:
                continue
            tag = m.group(1)
            self.chunks[tag] = block
            ids.append(tag)
            docs.append(block)

        self.collection.add(ids=ids, documents=docs)
        logger.info("Loaded %d PDPA chunks into ChromaDB", len(ids))

    def _init_llm(self):
        """Initialize the selected LLM backend."""
        self.backend = LLM_BACKEND
        if self.backend == "gemini":
            from google import genai
            api_key = os.environ.get("GEMINI_API_KEY")
            if not api_key:
                raise RuntimeError("GEMINI_API_KEY not set for gemini backend")
            self.gemini = genai.Client(api_key=api_key)
            logger.info("LLM backend: Gemini (%s)", GEMINI_MODEL)
        else:
            # Ollama — verify reachable and warm the model.
            try:
                r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
                r.raise_for_status()
                logger.info("LLM backend: Ollama (%s) at %s", OLLAMA_MODEL, OLLAMA_URL)
                # Warm the model into RAM so the first real call isn't cold.
                requests.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={"model": OLLAMA_MODEL, "prompt": "ready", "stream": False},
                    timeout=120,
                )
                logger.info("Ollama model warmed")
            except Exception as e:
                logger.warning("Ollama not reachable/warmable at %s: %s", OLLAMA_URL, e)

    # --- retrieval ---

    def retrieve(self, query: str, k: int = TOP_K) -> list:
        """Return top-k (tag, text) tuples most relevant to the query."""
        res = self.collection.query(query_texts=[query], n_results=k)
        tags = res["ids"][0]
        docs = res["documents"][0]
        return list(zip(tags, docs))

    def _build_prompt(self, pii_types: list, jurisdiction: str,
                      classification: str, context: str) -> str:
        """Construct the PDPA reasoning prompt. Shared by evaluate() and evaluate_fast()."""
        return f"""You are a PDPA compliance engine. Apply Singapore's PDPA \
Transfer Limitation Obligation to the transfer described below.

TRANSFER:
  Personal data types detected: {pii_types}
  Destination jurisdiction: {jurisdiction}
  Jurisdiction classification: {classification}

RETRIEVED PDPA CLAUSES:
{context}

DECISION PROCEDURE (follow exactly):
  1. If classification is EQUIVALENT, the transfer is permitted -> verdict = ALLOW.
  2. If classification is NON_EQUIVALENT, the transfer is not permitted
     without a documented safeguard -> verdict = BLOCK.

Then select the ONE clause tag above that legally supports your verdict, and write
a one-sentence reason that states WHY, using the content of that clause.

CRITICAL: the reason must justify the verdict you chose. If verdict is ALLOW, the
reason must explain why the transfer is permitted. If verdict is BLOCK, the reason
must explain why it is prohibited. Do not restate the decision procedure.

Respond with ONLY a JSON object:
{{"verdict": "...", "reason": "...", "cited_clause": "..."}}
"""

    # --- reasoning ---

    def evaluate(self, pii_types: list, jurisdiction: str, classification: str) -> dict:
        """
        Produce a verdict for transferring the given PII to a jurisdiction.

        Args:
            pii_types: e.g. ["SG_NRIC", "EMAIL_ADDRESS"]
            jurisdiction: e.g. "US", "MY", "SG"
            classification: e.g. "NON_EQUIVALENT", "EQUIVALENT"

        Returns dict:
            {verdict, reason, cited_clause, citation_valid}
        """
        query = (
            f"Transfer of personal data containing {', '.join(pii_types)} "
            f"to {jurisdiction} ({classification} jurisdiction) under the "
            f"PDPA Transfer Limitation Obligation."
        )
        retrieved = self.retrieve(query)

        context = "\n\n".join(f"{tag}: {text}" for tag, text in retrieved)
        valid_tags = [tag for tag, _ in retrieved]

        prompt = f"""You are a PDPA compliance engine. Apply Singapore's PDPA \
Transfer Limitation Obligation to the transfer described below.

TRANSFER:
  Personal data types detected: {pii_types}
  Destination jurisdiction: {jurisdiction}
  Jurisdiction classification: {classification}

RETRIEVED PDPA CLAUSES:
{context}

DECISION PROCEDURE (follow exactly):
  1. If classification is EQUIVALENT, the transfer is permitted -> verdict = ALLOW.
  2. If classification is NON_EQUIVALENT, the transfer is not permitted
     without a documented safeguard -> verdict = BLOCK.

Then select the ONE clause tag above that legally supports your verdict, and write
a one-sentence reason that states WHY, using the content of that clause.

CRITICAL: the reason must justify the verdict you chose. If verdict is ALLOW, the
reason must explain why the transfer is permitted. If verdict is BLOCK, the reason
must explain why it is prohibited. Do not restate the decision procedure.

Respond with ONLY a JSON object:
{{"verdict": "...", "reason": "...", "cited_clause": "..."}}
"""

        try:
            if self.backend == "gemini":
                resp = self.gemini.models.generate_content(
                    model=GEMINI_MODEL, contents=prompt
                )
                text = resp.text.strip()
                text = re.sub(r"^```(json)?|```$", "", text, flags=re.MULTILINE).strip()
                result = json.loads(text)
            else:
                fast_verdict, result = self._call_ollama_streaming(prompt, valid_tags)
        except Exception as e:
            logger.warning("LLM reasoning failed: %s", e)
            return {
                "verdict": "BLOCK",
                "reason": f"Reasoning error, fail-secure block: {e}",
                "cited_clause": None,
                "citation_valid": False,
            }

        # --- Anti-hallucination: verify cited clause exists in corpus ---
        cited = result.get("cited_clause")
        result["citation_valid"] = cited in self.chunks
        if not result["citation_valid"]:
            logger.warning("LLM cited unknown clause '%s' — flagging", cited)

        return result

    def _call_ollama(self, prompt: str, valid_tags: list) -> dict:
        """Call Ollama with a JSON schema constraint for guaranteed-valid output."""
        schema = {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["BLOCK", "ALLOW"]},
                "reason": {"type": "string"},
                "cited_clause": {"type": "string", "enum": valid_tags},
            },
            "required": ["verdict", "reason", "cited_clause"],
        }
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "cited_clause": {"enum": valid_tags},          # token-level JSON schema enforcement
            "options": {"temperature": 0, "num_predict": 150},
        }
        r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=120)
        r.raise_for_status()
        response_text = r.json()["response"]
        result = json.loads(response_text)
        # Normalize: model sometimes emits "TAG: extra text" or "[TAG]".
        cited = result.get("cited_clause", "")
        m = re.search(r"[A-Z0-9\-]+", cited.replace("[", "").replace("]", ""))
        if m:
            result["cited_clause"] = m.group(0)
        return result

    def _call_ollama_streaming(self, prompt: str, valid_tags: list, on_verdict=None):
        """
        Stream from Ollama, returning (verdict, full_result_or_None).

        With grammar-constrained decoding the schema's field order is the
        generation order, so "verdict" arrives within the first few tokens.
        We return as soon as it is parseable; the caller can finish the rest
        in the background.

        Returns: (verdict_str, generator_that_yields_final_dict)
        """
        schema = {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["BLOCK", "ALLOW"]},
                "reason": {"type": "string"},
                "cited_clause": {"type": "string", "enum": valid_tags},
            },
            "required": ["verdict", "reason", "cited_clause"],
        }
        payload = {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": True,
            "format": schema,
            "options": {"temperature": 0, "num_predict": 150},
        }

        t_start = time.time()
        r = requests.post(f"{OLLAMA_URL}/api/generate", json=payload,
                          stream=True, timeout=120)
        r.raise_for_status()

        buffer = ""
        t_verdict = None
        verdict = None
        verdict_re = re.compile(r'"verdict"\s*:\s*"(BLOCK|ALLOW)"')

        for line in r.iter_lines():
            if not line:
                continue
            chunk = json.loads(line)
            buffer += chunk.get("response", "")

            # Emit the verdict the moment it is parseable.
            if verdict is None:
                m = verdict_re.search(buffer)
                if m:
                    verdict = m.group(1)
                    t_verdict = time.time() - t_start
                    logger.info("FAST VERDICT: %s at %.2fs", verdict, t_verdict)
                    if on_verdict:
                        on_verdict(verdict)
            if chunk.get("done"):
                break

        # Parse the completed JSON.
        try:
            result = json.loads(buffer)
        except Exception as e:
            logger.warning("streamed JSON parse failed: %s", e)
            result = {"verdict": verdict or "BLOCK", "reason": "", "cited_clause": ""}

        # Normalize the tag.
        cited = result.get("cited_clause", "")
        m = re.search(r"[A-Z0-9\-]+", cited.replace("[", "").replace("]", ""))
        if m:
            result["cited_clause"] = m.group(0)

        t_total = time.time() - t_start
        logger.info("FULL RESPONSE at %.2fs (verdict was %.2fs earlier)",
                    t_total, t_total - t_verdict if verdict else 0)

        return verdict or result.get("verdict", "BLOCK"), result

    def evaluate_fast(self, pii_types: list, jurisdiction: str,
                      classification: str, flow_id: str = "", on_complete=None) -> dict:
        """
        Return the verdict as soon as the model emits it (~5s), and finish
        generating the justification in a background thread (~30s).

        The completed result lands in justification_store[flow_id].
        """
        query = (
            f"Transfer of personal data containing {', '.join(pii_types)} "
            f"to {jurisdiction} ({classification} jurisdiction) under the "
            f"PDPA Transfer Limitation Obligation."
        )
        retrieved = self.retrieve(query)
        context = "\n\n".join(f"{tag}: {text}" for tag, text in retrieved)
        valid_tags = [tag for tag, _ in retrieved]
        prompt = self._build_prompt(pii_types, jurisdiction, classification,
                                    context)

        verdict_ready = threading.Event()
        holder = {"verdict": None, "result": None, "error": None}

        def worker():
            try:
                v, res = self._call_ollama_streaming(
                    prompt, valid_tags, on_verdict=lambda x: (
                        holder.update(verdict=x), verdict_ready.set()
                    )
                )
                holder["result"] = res
            except Exception as e:
                holder["error"] = str(e)
                holder["verdict"] = "BLOCK"      # fail-secure
            finally:
                verdict_ready.set()
                if flow_id:
                    justification_store[flow_id] = holder.get("result") or {
                        "verdict": holder.get("verdict", "BLOCK"),
                        "reason": f"Reasoning error: {holder.get('error')}",
                        "cited_clause": None,
                    }
                if on_complete:
                    try:
                        on_complete(justification_store.get(flow_id, {}))
                    except Exception as e:
                        logger.warning("on_complete failed: %s", e)

        threading.Thread(target=worker, daemon=True).start()

        # Wait only for the verdict, not the justification.
        got = verdict_ready.wait(timeout=30)
        verdict = holder.get("verdict") or "BLOCK"
        if not got:
            logger.warning("verdict timeout, fail-secure BLOCK")

        return {
            "verdict": verdict,
            "reason": "Justification generating asynchronously.",
            "cited_clause": None,
            "citation_valid": None,
            "flow_id": flow_id,
        }
        
# Module-level singleton (heavy: loads embeddings + corpus once).
_engine = None


def get_engine() -> RagEngine:
    global _engine
    if _engine is None:
        _engine = RagEngine()
    return _engine


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    eng = get_engine()
    print("\n--- Test: SG_NRIC to US ---")
    print(json.dumps(eng.evaluate(["SG_NRIC", "EMAIL_ADDRESS"], "US", "NON_EQUIVALENT"), indent=2))

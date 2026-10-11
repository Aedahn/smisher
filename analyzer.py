"""
analyzer.py  — Single‑Email Phishing Detector (DS Fusion + Explainer)
               Accepts pre‑parsed body and metadata, extracts URLs,
               runs three specialists, fuses with Dempster‑Shafer,
               and explains the verdict.
"""

import re, json, sys
from typing import Optional


def _resolve_model_name(raw: Optional[str]) -> str:
    return "gemma2_9b"


_selected_model_name = "gemma2_9b"
argv = sys.argv[1:]
for idx, arg in enumerate(argv):
    if arg == "--model" and idx + 1 < len(argv):
        _selected_model_name = _resolve_model_name(argv[idx + 1])
        break
    if arg.startswith("--model="):
        _selected_model_name = _resolve_model_name(arg.split("=", 1)[1])
        break

# ------------------------- CONFIG ----------------------------
OLLAMA_MODEL_NAME = "gemma2:9b"
TEMPERATURE = 0.0
MAX_TOKENS = 600

_ollama_name = OLLAMA_MODEL_NAME
_ollama_model_name = _ollama_name

import ollama as _ollama_lib

try:
    _ollama_lib.chat(model=_ollama_name,
                     messages=[{"role": "user", "content": "hi"}],
                     options={"num_predict": 3})
    print(f"✅ Ollama ready — {_ollama_name}\n", file=sys.stderr)
except Exception as e:
    print(f"❌ Ollama failed: {e}", file=sys.stderr)
    raise SystemExit(1)


# ------------------------- CALL MODEL -----------------------
def call_model(prompt):
    try:
        r = _ollama_lib.chat(
            model=_ollama_name,
            messages=[{"role":"user","content":prompt}],
            options={"temperature":TEMPERATURE, "num_predict":MAX_TOKENS, "think":False}
        )
        return r["message"]["content"]
    except Exception as e:
        print(f"Ollama error: {e}", file=sys.stderr)
        return None


# ------------------------- URL EXTRACTION --------------------
def extract_urls(text):
    """Return a newline‑separated string of URLs found in text, or the no‑URLs message."""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|hxxps?://[^\s<>"{}|\\^`\[\]]+'
    all_urls = list(dict.fromkeys(re.findall(url_pattern, text)))[:20]
    return '\n'.join(all_urls) if all_urls else "No URLs found in this email"


# ------------------------- JSON PARSER (specialists) ---------
def parse_json(text):
    if text is None:
        return {"verdict":"Error","confidence":0.5,"reason":"No response"}
    try:
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        text = re.sub(r"```json\s*", "", text)
        text = re.sub(r"```\s*", "", text).strip()
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            l = text.lower()
            v = ("Phishing" if "phish" in l
                 else "Legitimate" if "legit" in l or "safe" in l
                 else "Error")
            return {"verdict":v, "confidence":0.5, "reason":text[:200]}
        jt = re.sub(r",\s*}", "}", text[start:end+1])
        obj = json.loads(jt)
        raw = str(obj.get("verdict","")).lower()
        v = ("Phishing" if "phish" in raw
             else "Legitimate" if "legit" in raw or "safe" in raw or "ham" in raw or "benign" in raw
             else "Error")
        try:
            c = float(obj.get("confidence", 0.5))
            c = max(0.0, min(1.0, c))
        except Exception:
            c = 0.5
        reason = str(obj.get("reason", obj.get("explanation","No reason")))[:300]
        return {"verdict":v, "confidence":c, "reason":reason}
    except Exception:
        l = text.lower()
        v = ("Phishing" if "phish" in l
             else "Legitimate" if "legit" in l or "safe" in l
             else "Error")
        return {"verdict":v, "confidence":0.5, "reason":f"Recovered: {text[:150]}"}


# =====================================================================
# SPECIALIST PROMPTS (unchanged from final version)
# =====================================================================

_TEXT_PROMPT = """You are a cybersecurity analyst. Determine whether the email body contains evidence of deception, social engineering, credential theft, financial fraud, impersonation, or other malicious intent.

Important principles:
- Do not assume phishing merely because the email contains urgency, deadlines, reminders, warnings, promotions, or account-related content.
- Routine business communication, newsletters, transactional notifications, and personal correspondence without deception are often legitimate.
- A phishing verdict requires evidence that the sender is attempting to deceive, manipulate, impersonate, steal information, or induce an unsafe action.
- If no clear deception is present, classify the email as Legitimate.
- Do not invent missing context.

Deception patterns include:
- Malicious urgency or fear: threats, account suspension, legal consequences, or pressure for immediate security‑sensitive action.
- Requests for sensitive information (passwords, payment details, personal identification).
- Impersonation of a trusted entity (bank, government, brand, colleague).
- Generic greetings that avoid personalization.
- Promises of money, prizes, or jobs that seem too good to be true, or advance‑fee requests.
- Romance or friendship scams: strangers quickly building emotional connection then asking for money.

Use low confidence when evidence is weak, higher confidence when evidence is strong.

EMAIL BODY:
\"\"\"
{body}
\"\"\"

Output ONLY a valid JSON object. No markdown.
Example: {{"verdict": "Phishing", "confidence": 0.91, "reason": "The email demands immediate password verification, a classic credential‑harvesting tactic."}}

Rules:
- verdict: exactly "Phishing" or "Legitimate"
- confidence: a decimal between 0.0 and 1.0
- reason: one sentence naming the specific signal (or stating none found)"""


_URL_PROMPT = """You are a cybersecurity analyst evaluating URLs found in an email.

Analyze the URLs below. Do not use any external context.

URLS TO ANALYZE:
\"\"\"
{urls}
\"\"\"

EVALUATION RULES:

1. If no URLs are present: return Legitimate at 0.50 confidence.
2. Examine the **registrable domain** (main domain plus TLD).
   - Multiple subdomain levels alone are NOT suspicious.
   - A subdomain of a trusted domain is not phishing; only treat a subdomain as suspicious when it contains a known brand name and the registrable domain is clearly unrelated.
3. Phishing indicators:
   - The registrable domain misspells a known brand (typosquatting).
   - Unicode lookalikes in the domain.
   - An IP address used as a hostname.
   - A credential‑harvesting path (/verify, /confirm, /restore, /validate, /update) on a domain that already raises other concerns.
   - A page collecting login or payment details over HTTP (not HTTPS).
   - URL shorteners (e.g. bit.ly, tinyurl.com) are mild signals; require at least one additional indicator to classify as Phishing.
4. The following are NOT phishing indicators by themselves:
   - An unfamiliar domain.
   - A long URL, multiple subdomains, or URL parameters.
   - Account‑related paths such as /login, /account, /update.
   - Login pages on legitimate domains.
5. A URL should NOT be classified as phishing unless at least one concrete indicator is identified.
6. If no phishing indicator is present, return:
   {{"verdict":"Legitimate","confidence":0.50,"reason":"No phishing indicators found in the URLs."}}

Confidence: use 0.50 exactly when no URLs or no indicators, higher for concrete findings, moderate for ambiguous signals.

Output ONLY valid JSON. No markdown.
Format: {{"verdict": "Phishing", "confidence": 0.87, "reason": "One sentence naming the specific indicator."}}"""


_METADATA_PROMPT = """You are a cybersecurity analyst specializing in email headers.

Analyze ONLY the headers below. Do not consider the body or URLs.

You may flag the email as Phishing only when concrete, high‑confidence signals are present.
The absence of authentication, an unfamiliar domain, or time‑sensitive subject lines are NOT phishing indicators by themselves.

Look for these signals:

1. **Display‑name impersonation**
   The display name explicitly claims a specific organization (bank, IT support, well‑known brand, government), BUT the actual sender address does NOT belong to that entity.
   Generic names ("John", "Admin", "Support") are NOT impersonation.

2. **Lookalike domain**
   The sender domain is designed to imitate a recognizable organization while falsely presenting itself as that organization (misspellings, character substitution, added words).
   The mere presence of a brand name in a domain is not sufficient evidence of impersonation.

3. **Free‑email provider impersonating a known entity**
   Sender uses gmail.com, yahoo.com, hotmail.com etc. while the display name claims to be a company or government body.

4. **Reply‑To mismatch (supporting only)**
   Not sufficient alone. If identity deception is already present (signals 1‑3), a Reply‑To pointing to an unrelated destination strengthens the phishing assessment.

If NONE of the above are present, the correct verdict is Legitimate.
Return Legitimate with low confidence and state that no anomalies were found. Do NOT invent indicators.

EMAIL HEADERS:
\"\"\"
{metadata}
\"\"\"

Output ONLY a valid JSON object. No markdown.
Example: {{"verdict": "Phishing", "confidence": 0.87, "reason": "Display name Wells Fargo but sender domain is npaccounting.net."}}

Rules:
- verdict: exactly "Phishing" or "Legitimate"
- confidence: a decimal between 0.0 and 1.0
- reason: exactly one sentence
- If headers say "No metadata available" or are very minimal:
  output exactly: {{"verdict": "Legitimate", "confidence": 0.50, "reason": "Insufficient header data to analyze."}}"""


# =====================================================================
# EXPLAINER PROMPT (separate LLM, no decision power)
# =====================================================================
_EXPLAINER_PROMPT = """You are a friendly email security assistant.
Your job is to explain a security decision to a non‑technical user.

You are given the individual verdicts, confidences, and reasons from three
specialist checks (text content, links, sender information), plus the final
verdict that was reached.

IMPORTANT: The final verdict is already determined. Do NOT second‑guess it.
Simply explain why the email was classified that way.

The three specialist checks:
1. Text content: {text_verdict} (confidence: {text_conf:.0%}) — {text_reason}
2. Links in the email: {url_verdict} (confidence: {url_conf:.0%}) — {url_reason}
3. Sender information: {meta_verdict} (confidence: {meta_conf:.0%}) — {meta_reason}

Final decision: {final_verdict}

Write 2‑3 short sentences in plain English.
- Use everyday words. Do NOT use SPF, DKIM, TLD, typosquat, etc.
- Mention the most important reason(s) why the email was flagged or allowed.
- No bullet points, no markdown.
- Do not mention the names of the three checks (e.g., "text content", "links in the email", "sender information").
  Instead, weave the facts into natural language."""


# =====================================================================
# DEMPSTER‑SHAFER FUSION
# =====================================================================

def build_mass(verdict, confidence, is_url_agent=False):
    if is_url_agent and verdict == "Legitimate" and confidence == 0.50:
        return (0.0, 0.0, 1.0)
    if verdict not in ("Phishing", "Legitimate"):
        return (0.0, 0.0, 1.0)
    if verdict == "Phishing":
        return (confidence, 0.0, 1.0 - confidence)
    else:
        return (0.0, confidence, 1.0 - confidence)


def combine_two(m1, m2):
    m1_P, m1_L, m1_F = m1
    m2_P, m2_L, m2_F = m2
    K = m1_P * m2_L + m1_L * m2_P
    if K == 1.0:
        return (1/3, 1/3, 1/3)
    denom = 1.0 - K
    combined_P = (m1_P * m2_P + m1_P * m2_F + m1_F * m2_P) / denom
    combined_L = (m1_L * m2_L + m1_L * m2_F + m1_F * m2_L) / denom
    combined_F = (m1_F * m2_F) / denom
    return (combined_P, combined_L, combined_F)


def ds_fusion(t, u, m):
    m_text = build_mass(t["verdict"], t["confidence"])
    m_url  = build_mass(u["verdict"], u["confidence"], is_url_agent=True)
    m_meta = build_mass(m["verdict"], m["confidence"])
    m_comb = combine_two(m_text, m_url)
    m_final = combine_two(m_comb, m_meta)
    betP_Phish = m_final[0] + 0.5 * m_final[2]
    final_verdict = "Phishing" if betP_Phish > 0.5 else "Legitimate"
    return final_verdict, betP_Phish


# =====================================================================
# THE THREE SPECIALISTS
# =====================================================================

def text_agent(body):
    return parse_json(call_model(_TEXT_PROMPT.format(body=body)))

def url_agent(urls):
    if not urls or "No URLs found" in urls:
        return {"verdict":"Legitimate","confidence":0.50,"reason":"No URLs present to analyze."}
    return parse_json(call_model(_URL_PROMPT.format(urls=urls)))

def metadata_agent(metadata):
    return parse_json(call_model(_METADATA_PROMPT.format(metadata=metadata)))


# =====================================================================
# EXPLAINER AGENT
# =====================================================================

def explainer_agent(t, u, m, final_verdict):
    prompt = _EXPLAINER_PROMPT.format(
        text_verdict=t["verdict"],
        text_conf=t["confidence"],
        text_reason=t["reason"],
        url_verdict=u["verdict"],
        url_conf=u["confidence"],
        url_reason=u["reason"],
        meta_verdict=m["verdict"],
        meta_conf=m["confidence"],
        meta_reason=m["reason"],
        final_verdict=final_verdict,
    )
    resp = call_model(prompt)
    if resp is None:
        return "Explanation unavailable."
    return re.sub(r"<think>.*?</think>", "", resp, flags=re.DOTALL).strip()


# =====================================================================
# SINGLE‑EMAIL ANALYSIS (expects pre‑parsed body + metadata)
# =====================================================================

def process_email(body, metadata, explain=True):
    """
    Analyze a single email given its body text and headers (metadata).
    URLs are extracted from the body automatically.
    Returns a dictionary with all specialist results, DS‑fused verdict,
    phishing score, and optional plain‑English explanation.
    """
    try:
        # Extract URLs from the body (the original raw text is not available,
        # but body contains the email content; URLs will be found if present).
        urls = extract_urls(body)

        # Run the three specialists
        t = text_agent(body)
        u = url_agent(urls)
        m = metadata_agent(metadata)

        # Dempster‑Shafer fusion
        final_verdict, phishing_score = ds_fusion(t, u, m)

        # Explainer
        final_reason = explainer_agent(t, u, m, final_verdict) if explain else "Explanation skipped."

        return {
            "text_verdict":     t["verdict"],
            "text_confidence":  t["confidence"],
            "text_reason":      t["reason"],
            "url_verdict":      u["verdict"],
            "url_confidence":   u["confidence"],
            "url_reason":       u["reason"],
            "meta_verdict":     m["verdict"],
            "meta_confidence":  m["confidence"],
            "meta_reason":      m["reason"],
            "final_verdict":    final_verdict,
            "phishing_score":   round(phishing_score, 4),
            "explanation":      final_reason,
            "model":            _selected_model_name,
        }

    except Exception as e:
        return {
            "text_verdict":    "Error", "text_confidence": 0.5, "text_reason": "",
            "url_verdict":     "Error", "url_confidence":  0.5, "url_reason":  "",
            "meta_verdict":    "Error", "meta_confidence": 0.5, "meta_reason": "",
            "final_verdict":   "Error",
            "phishing_score":  0.5,
            "explanation":     f"Fatal error: {str(e)[:200]}",
            "model":           _selected_model_name,
        }


# =====================================================================
# Command‑line interface (stdin JSON → stdout JSON)
# =====================================================================
def _handle_request(input_data):
    global _selected_model_name
    body = input_data["body"]
    metadata = input_data.get("metadata", "")
    requested_model = input_data.get("model")
    if requested_model:
        _selected_model_name = _resolve_model_name(requested_model)
    return process_email(body, metadata, explain=True)


if __name__ == "__main__":
    serve_mode = "--serve" in sys.argv
    if serve_mode:
        print("READY", flush=True, file=sys.stderr)
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                input_data = json.loads(line)
                result = _handle_request(input_data)
                print(json.dumps(result), flush=True)
            except Exception as e:
                print(json.dumps({"error": str(e)}), flush=True)
    else:
        try:
            input_data = json.load(sys.stdin)
            result = _handle_request(input_data)
            print(json.dumps(result))
        except Exception as e:
            print(json.dumps({"error": str(e)}))
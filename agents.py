"""
agents.py  — Multi‑Agent Phishing Detection Architecture
             Three specialist analyzers (Text, URL, Metadata)
             + one decision agent (Judge).
             Principle‑based prompts, anti‑invention rules,
             independent specialists, logging, ultra‑robust fallback.
"""

import re, json, time

# ------------------------- CONFIG ----------------------------
MODEL_TO_LOAD = "B"          # A=Qwen3 8B, B=Gemma2 9B
OLLAMA_MODEL_A = "qwen3:8b"
OLLAMA_MODEL_B = "gemma2:9b"
MLX_MODEL_A =  "mlx-community/Qwen3-8B-4bit"
MLX_MODEL_B = ""   # Gemma2 not available via MLX
TEMPERATURE = 0.0
MAX_TOKENS  = 600

if MODEL_TO_LOAD == "A":
    _ollama_name = OLLAMA_MODEL_A
    _mlx_name = MLX_MODEL_A
elif MODEL_TO_LOAD == "B":
    _ollama_name = OLLAMA_MODEL_B
    _mlx_name = MLX_MODEL_B
else:
    raise ValueError(f"Unsupported MODEL_TO_LOAD: {MODEL_TO_LOAD}")

_ollama_model_name = _ollama_name

_mlx_model    = None
_mlx_generate = None
_use_mlx      = False

if _mlx_name:
    try:
        from mlx_lm import load as _mlx_load, generate as _mlx_gen
        print(f"Loading {_mlx_name} via MLX...")
        _mlx_model    = _mlx_load(_mlx_name)
        _mlx_generate = _mlx_gen
        _use_mlx      = True
        print("✅ MLX loaded\n")
    except Exception as e:
        print(f"MLX failed ({e}), using Ollama\n")

if not _use_mlx:
    import ollama as _ollama_lib
    try:
        _ollama_lib.chat(model=_ollama_name,
                         messages=[{"role":"user","content":"hi"}],
                         options={"num_predict":3})
        print(f"✅ Ollama ready — {_ollama_name}\n")
    except Exception as e:
        print(f"❌ Ollama failed: {e}")
        raise SystemExit(1)


# ------------------------- CALL MODEL -----------------------
def call_model(prompt):
    if _use_mlx and _mlx_model is not None:
        try:
            model, tokenizer = _mlx_model
            messages = [{"role":"user","content":prompt}]
            try:
                fmt = tokenizer.apply_chat_template(
                    messages, tokenize=False,
                    add_generation_prompt=True, enable_thinking=False
                )
            except TypeError:
                fmt = tokenizer.apply_chat_template(
                    messages, tokenize=False, add_generation_prompt=True
                )
            resp = _mlx_generate(model, tokenizer, prompt=fmt,
                                 max_tokens=MAX_TOKENS, verbose=False)
            return resp.strip() if resp else None
        except Exception as e:
            print(f"MLX error: {e}")

    try:
        r = _ollama_lib.chat(
            model=_ollama_name,
            messages=[{"role":"user","content":prompt}],
            options={"temperature":TEMPERATURE, "num_predict":MAX_TOKENS, "think":False}
        )
        return r["message"]["content"]
    except Exception as e:
        print(f"Ollama error: {e}")
        return None


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
# SPECIALIST PROMPTS
# NOTE: All JSON examples use {{ and }} (doubled braces) so that
#       str.format() does not treat them as format placeholders.
#       Single {body}, {urls}, {metadata} etc. remain as real placeholders.
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
# JUDGE PROMPT (balanced, anti‑invention, evidence‑quality conflict resolution)
# =====================================================================

_JUDGE_PROMPT = """You are a cybersecurity expert making the final decision on whether an email is phishing or legitimate.
You have the analyses from three specialist analyzers (text, URL, metadata).
Weigh their evidence fairly.

Important:
- High‑confidence Phishing verdicts are strong evidence of malice.
- High‑confidence Legitimate verdicts are strong evidence that no phishing indicators were identified by that specialist.
- Low confidence or neutral scores (0.50‑0.65) carry less weight.
- The URL agent returning Legitimate with confidence exactly 0.50 means no URL evidence was found.
  Treat this as neutral evidence, not evidence that the email is safe.

A phishing verdict requires at least one concrete phishing indicator identified by a specialist.
You may ONLY use evidence explicitly mentioned by the specialists.
Do NOT invent new phishing indicators.
If no specialist identifies a concrete phishing indicator, the final verdict must be Legitimate.

Unfamiliar domains, missing authentication data, generic display names, or uncertainty
are NOT phishing indicators.

When specialists disagree, prioritize the quality of the evidence, not the number of
agents supporting a verdict. A concrete phishing indicator (credential harvesting,
brand impersonation, typosquatting, deceptive sender identity, etc.) may outweigh
multiple neutral assessments. Multiple neutral or weak concerns do not automatically
outweigh a strong, well‑supported legitimate assessment.

When the text specialist has identified no evidence of deception with
confidence above 0.70, and the URL and metadata specialists have not
named a concrete specific indicator, the verdict is Legitimate.
The absence of evidence from URL and metadata analysis is not evidence
of phishing.

Output a JSON object with exactly these fields:
- verdict: "Phishing" or "Legitimate"
- confidence: your confidence (0.0‑1.0)
- explanation: 2‑3 plain‑English sentences explaining the decision to a non‑technical user.
  Avoid technical terms (SPF, DKIM, TLD, typosquat, etc.).
  Do NOT list what each agent said. Simply explain why the email is safe or suspicious.

Example: {{"verdict": "Phishing", "confidence": 0.91, "explanation": "The email creates false urgency about a suspended account and uses a misspelled domain that impersonates a real bank. The sender address does not match the claimed organization."}}

Here are the analyses:
1. Text: {text_verdict} (confidence: {text_conf:.2f}) — {text_reason}
2. Links: {url_verdict} (confidence: {url_conf:.2f}) — {url_reason}
3. Sender: {meta_verdict} (confidence: {meta_conf:.2f}) — {meta_reason}

Now give your final verdict, confidence, and explanation."""


# =====================================================================
# JUDGE PARSER (ultra‑robust)
# =====================================================================

def parse_judge_output(text, t, u, m):
    def fallback_conf(v):
        agents = [t.get("verdict","Error"), u.get("verdict","Error"), m.get("verdict","Error")]
        agree = sum(1 for a in agents if a == v)
        if agree == 3: return 0.90
        elif agree == 2: return 0.75
        else: return 0.55

    try:
        if text is None:
            return {"verdict":"Error","confidence":0.5,"explanation":"No response"}

        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
        cleaned = re.sub(r"```json\s*", "", cleaned)
        cleaned = re.sub(r"```\s*", "", cleaned).strip()

        try:
            start, end = cleaned.find("{"), cleaned.rfind("}")
            if start != -1 and end != -1 and end > start:
                jt = re.sub(r",\s*}", "}", cleaned[start:end+1])
                obj = json.loads(jt)
                raw = str(obj.get("verdict","")).lower()
                v = ("Phishing" if "phish" in raw
                     else "Legitimate" if "legit" in raw or "safe" in raw
                     else "Error")
                c = max(0.0, min(1.0, float(obj.get("confidence", 0.5))))
                exp = str(obj.get("explanation", obj.get("reason", "No explanation")))
                return {"verdict":v, "confidence":c, "explanation":exp}
        except Exception:
            pass

        lower = cleaned.lower()
        verdict = ("Phishing" if "phish" in lower
                   else "Legitimate" if "legit" in lower or "safe" in lower
                   else "Error")
        conf = fallback_conf(verdict)
        m_conf = re.search(r"(?:confidence|conf)\s*[:=]\s*([\d.]+)", lower)
        if m_conf:
            try:
                conf = max(0.0, min(1.0, float(m_conf.group(1))))
            except Exception:
                pass

        m_exp = re.search(r"(?:explanation|reason)\s*[:=]\s*(.+)", cleaned, re.IGNORECASE|re.DOTALL)
        explanation = m_exp.group(1).strip().strip('"\'') if m_exp else cleaned[:400].strip()

        return {"verdict":verdict, "confidence":conf, "explanation":explanation}

    except Exception:
        return {"verdict":"Error","confidence":0.5,"explanation":"Judge parser failed completely."}


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
# JUDGE AGENT — LLM final decision + plain‑English explanation
# =====================================================================

def judge_agent(t, u, m):
    prompt = _JUDGE_PROMPT.format(
        text_verdict=t.get("verdict", "Error"),
        text_conf=t.get("confidence", 0.5),
        text_reason=t.get("reason", ""),
        url_verdict=u.get("verdict", "Error"),
        url_conf=u.get("confidence", 0.5),
        url_reason=u.get("reason", ""),
        meta_verdict=m.get("verdict", "Error"),
        meta_conf=m.get("confidence", 0.5),
        meta_reason=m.get("reason", ""),
    )
    resp = call_model(prompt)
    result = parse_judge_output(resp, t, u, m)
    result["_raw_judge_response"] = resp   # kept for debugging
    return result


# =====================================================================
# FULL PIPELINE (ultra‑robust)
# =====================================================================

def process_email(body, urls, metadata, true_label=-1, explain=True):
    try:
        t = text_agent(body)
        u = url_agent(urls)
        m = metadata_agent(metadata)

        if explain:
            judge = judge_agent(t, u, m)

            if judge.get("verdict", "Error") == "Error":
                print(f"\n  [DEBUG] Judge raw: {str(judge.get('_raw_judge_response','N/A'))[:200]}")

            final_verdict = judge.get("verdict", "Error")
            final_reason  = judge.get("explanation", "No explanation")
            judge_conf    = judge.get("confidence", 0.5)
        else:
            votes = [t.get("verdict","Error"), u.get("verdict","Error"), m.get("verdict","Error")]
            final_verdict = "Phishing" if votes.count("Phishing") >= 2 else "Legitimate"
            judge_conf    = 0.5
            final_reason  = "No explanation (judge skipped)."

        predicted = 1 if final_verdict == "Phishing" else 0
        correct   = int(predicted == true_label) if true_label != -1 else -1

        phishing_score = judge_conf if final_verdict == "Phishing" else 1.0 - judge_conf

        return {
            "true_label":       true_label,
            "predicted":        predicted,
            "correct":          correct,
            "predicted_label":  final_verdict,
            "phishing_score":   round(phishing_score, 4),
            "dominant_agent":   "judge",
            "text_verdict":     t.get("verdict",""),
            "text_confidence":  t.get("confidence", 0.5),
            "text_reason":      t.get("reason",""),
            "url_verdict":      u.get("verdict",""),
            "url_confidence":   u.get("confidence", 0.5),
            "url_reason":       u.get("reason",""),
            "meta_verdict":     m.get("verdict",""),
            "meta_confidence":  m.get("confidence", 0.5),
            "meta_reason":      m.get("reason",""),
            "has_error":        int(
                t.get("verdict","") == "Error" or
                u.get("verdict","") == "Error" or
                m.get("verdict","") == "Error"
            ),
            "final_reason":     final_reason,
            "model":            _mlx_name if _use_mlx else _ollama_name,
            "judge_agrees_text": int(t.get("verdict","") == final_verdict),
            "judge_agrees_url":  int(u.get("verdict","") == final_verdict),
            "judge_agrees_meta": int(m.get("verdict","") == final_verdict),
        }

    except Exception as e:
        return {
            "true_label":      true_label,
            "predicted":       -1,
            "correct":         -1,
            "predicted_label": "Error",
            "phishing_score":  0.5,
            "dominant_agent":  "fallback",
            "text_verdict":    "Error", "text_confidence": 0.5, "text_reason":  "",
            "url_verdict":     "Error", "url_confidence":  0.5, "url_reason":   "",
            "meta_verdict":    "Error", "meta_confidence": 0.5, "meta_reason":  "",
            "has_error":       1,
            "final_reason":    f"Fatal error: {str(e)[:200]}",
            "model":           _mlx_name if _use_mlx else _ollama_name,
            "judge_agrees_text": 0, "judge_agrees_url": 0, "judge_agrees_meta": 0,
        }


# =====================================================================
# SELF-TEST
# =====================================================================

def test_setup():
    tests = [
        {
            "name":  "PHISHING — must be caught",
            "body":  (
                "Dear Account Holder, unusual login activity has been detected on your "
                "PayPal account. Your account is TEMPORARILY LIMITED. Verify your "
                "information IMMEDIATELY or your account will be permanently closed "
                "within 24 hours. Click the link to restore access now."
            ),
            "urls":  "https://paypa1-secure-verify.xyz/restore?user=8827364",
            "meta":  (
                "From: \"PayPal Security\" <security@paypa1-secure-verify.xyz>\n"
                "Reply-To: credentials@gmail.com\n"
                "Subject: URGENT: Your PayPal Account Has Been Limited"
            ),
            "label": 1,
        },
        {
            "name":  "LEGITIMATE — must pass through",
            "body":  (
                "Hi Sarah, just confirming our meeting is still on for tomorrow at 2pm "
                "in conference room B. I will bring the Q1 reports we discussed. "
                "Let me know if you need to reschedule. Best, Michael"
            ),
            "urls":  "No URLs found in this email",
            "meta":  (
                "From: michael.johnson@acmecorp.com\n"
                "To: sarah.smith@acmecorp.com\n"
                "Subject: Meeting tomorrow 2pm — still on?"
            ),
            "label": 0,
        },
    ]

    print("=" * 60)
    print("SELF-TEST — Multi‑Agent Phishing Detection Architecture")
    print(f"Engine: {'MLX' if _use_mlx else 'Ollama'}")
    print(f"Model:  {_mlx_name if _use_mlx else _ollama_name}")
    print(f"Three specialist analyzers + Judge decision agent")
    print("=" * 60)

    all_passed = True

    for tc in tests:
        print(f"\n{tc['name']}")
        t0     = time.time()
        result = process_email(
            tc["body"], tc["urls"], tc["meta"],
            true_label=tc["label"], explain=True
        )
        elapsed = time.time() - t0

        passed = (result["correct"] == 1) and (result["has_error"] == 0)
        if not passed:
            all_passed = False

        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {status} → {result['predicted_label']} "
              f"score={result['phishing_score']:.3f}  "
              f"has_error={result['has_error']}  time={elapsed:.1f}s")
        print(f"  Text:     {result['text_verdict']} ({result['text_confidence']:.0%}) "
              f"— {result['text_reason'][:55]}")
        print(f"  URL:      {result['url_verdict']}  ({result['url_confidence']:.0%}) "
              f"— {result['url_reason'][:55]}")
        print(f"  Metadata: {result['meta_verdict']} ({result['meta_confidence']:.0%}) "
              f"— {result['meta_reason'][:55]}")
        print(f"  Judge:    {result['predicted_label']}  |  "
              f"Explanation: {result['final_reason'][:150]}")
        print(f"  Agreement: text={result['judge_agrees_text']} "
              f"url={result['judge_agrees_url']} meta={result['judge_agrees_meta']}")

        if not passed:
            if result["has_error"] == 1:
                print(f"\n  DIAGNOSIS: An agent returned Error. Raise MAX_TOKENS to 768.")
            else:
                print(f"\n  DIAGNOSIS: Wrong prediction. Check which agent gave unexpected verdict.")

    print("\n" + "=" * 60)
    if all_passed:
        print(f"ALL TESTS PASSED — {'MLX ✅' if _use_mlx else 'Ollama ✅'}")
        print("Ready for: caffeinate -i python3 run_pipeline.py")
    else:
        print("SOME TESTS FAILED — fix before running pipeline.")
    print("=" * 60)

def save_execution_time(model_name, start_time, output_dir="results"):
    """
    Write the total pipeline execution time to a text file named after the model.
    Call this from run_pipeline.py after all emails have been processed.
    """
    import os
    elapsed = time.time() - start_time
    os.makedirs(output_dir, exist_ok=True)
    safe_name = model_name.replace(':', '_').replace('.', '_')
    filepath = os.path.join(output_dir, f"{safe_name}_time.txt")
    with open(filepath, 'w') as f:
        f.write(f"Model: {model_name}\n")
        f.write(f"Total pipeline time: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)\n")
    print(f"Execution time saved to {filepath}")

if __name__ == "__main__":
    test_setup()
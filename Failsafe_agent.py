%%writefile failsafe_agent.py
import os, uuid, re, ast, unicodedata
from collections import Counter
from math import sqrt

ALLOWED_MODELS = {"gpt-4o-mini", "gpt-4o"}
MAX_OUTPUT_CHARS = 4000

# -----------------------------
# Helpers
# -----------------------------
def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).strip()

def _truncate(s: str, limit: int) -> tuple[str, bool]:
    return (s[:limit], len(s) > limit)

def _extract_code_block(query: str) -> str | None:
    start = query.find("```")
    if start == -1: return None
    end = query.find("```", start + 3)
    if end == -1: return None
    return query[start + 3:end].strip()

# -----------------------------
# Input Restriction
# -----------------------------
SENSITIVE_CATEGORIES = {
    "self_harm": [r"\bsuicide\b", r"\bkill myself\b", r"\bself harm\b"],
    "violence": [r"\bkill\b", r"\bmake a bomb\b", r"\battack\b"],
    "illegal": [r"\bhack\b", r"\bcredit card\b", r"\bwifi password\b", r"\bcrack\b"],
    "personal_data": [r"\bssn\b", r"\baadhaar\b", r"\bpan\b", r"\bupi\b", r"\bpassword\b"],
}

def input_restriction_check(text: str, max_len: int = 5000) -> tuple[str,str]:
    if not text or len(text.strip()) < 3:
        return "blocked", "Empty/too short query"
    if len(text) > max_len:
        return "blocked", f"Query too long ({len(text)} chars). Limit: {max_len}"
    lower = text.lower()
    for cat, patterns in SENSITIVE_CATEGORIES.items():
        for p in patterns:
            if re.search(p, lower):
                return "blocked", f"Sensitive content: {cat}"
    return "passed", "OK"

# -----------------------------
# Malicious Code Check
# -----------------------------
DANGEROUS_PATTERNS = [
    r"\bos\.system\s*\(",
    r"\bsubprocess\.(Popen|run|call)\s*\(",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\brm\s+-rf\b",
]

FORBIDDEN_CALL_NAMES = {"eval","exec","compile","os.system","subprocess.Popen","subprocess.call","subprocess.run"}

def contains_dangerous_strings(s: str) -> list[str]:
    s_lower = s.lower()
    return [pat for pat in DANGEROUS_PATTERNS if re.search(pat, s_lower)]

def malicious_code_check(query: str, code_snippet: str | None = None) -> tuple[str,str]:
    hits = contains_dangerous_strings(query)
    if hits:
        return "blocked", f"Dangerous patterns: {hits}"
    if code_snippet:
        try:
            tree = ast.parse(code_snippet)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALL_NAMES:
                        return "blocked", f"Forbidden call: {node.func.id}"
        except SyntaxError:
            return "blocked", "Syntax error in code block"
    return "passed", "OK"

# -----------------------------
# Plagiarism Check
# -----------------------------
def _normalize_text(s: str) -> str:
    s = s.lower()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"[^a-z0-9\s]", "", s)
    return s.strip()

def cosine_token(a: str, b: str) -> float:
    A = Counter(_normalize_text(a).split())
    B = Counter(_normalize_text(b).split())
    dot = sum(A[t]*B[t] for t in set(A)|set(B))
    magA = sqrt(sum(v*v for v in A.values()))
    magB = sqrt(sum(v*v for v in B.values()))
    return dot/(magA*magB+1e-9)

def plagiarism_check(generated: str, corpus: list[str], cosine_thresh: float=0.85) -> tuple[str,str]:
    best = {"source_idx":None,"cosine":0.0}
    for i,ref in enumerate(corpus):
        cos = cosine_token(generated,ref)
        if cos>best["cosine"]:
            best={"source_idx":i,"cosine":cos}
    if best["cosine"]>=cosine_thresh:
        return "flagged", f"Similarity {best['cosine']:.2f} with corpus[{best['source_idx']}]"
    return "passed", "OK"

# -----------------------------
# Dummy LLM + Safety Filter
# -----------------------------
class DummyLLM:
    def __init__(self,name,key): self.name=name; self.key=key
    def invoke(self,prompt): return {"content":f"Echo from {self.name}: {prompt[:200]}"}

def llm_safety_filter(llm, query: str) -> tuple[str,str]:
    if "hack" in query.lower() or "rm -rf" in query.lower():
        return "blocked", "LLM safety filter flagged"
    return "passed", "OK"

# -----------------------------
# Pipeline
# -----------------------------
def answer_pipeline(user_query: str, reference_corpus: list[str], model_name: str="gpt-4o-mini"):
    trace_id=str(uuid.uuid4())[:8]
    user_query=_normalize(user_query)
    results = {}

    # Input restriction
    status,reason = input_restriction_check(user_query)
    results["Input Restriction"] = {"status":status,"reason":reason}
    if status=="blocked": return {"trace":trace_id,"checks":results,"final":"blocked"}

    # Malicious code
    code_block=_extract_code_block(user_query)
    status,reason = malicious_code_check(user_query,code_block)
    results["Malicious Code"] = {"status":status,"reason":reason}
    if status=="blocked": return {"trace":trace_id,"checks":results,"final":"blocked"}

    # LLM safety filter
    llm=DummyLLM(model_name,"dummy_key")
    status,reason = llm_safety_filter(llm,user_query)
    results["LLM Safety Filter"] = {"status":status,"reason":reason}
    if status=="blocked": return {"trace":trace_id,"checks":results,"final":"blocked"}

    # Invoke dummy LLM
    resp=llm.invoke(user_query)
    content,_=_truncate(resp["content"],MAX_OUTPUT_CHARS)

    # Plagiarism
    status,reason = plagiarism_check(content,reference_corpus)
    results["Plagiarism"] = {"status":status,"reason":reason}
    if status=="flagged": return {"trace":trace_id,"checks":results,"final":"plagiarism_flagged"}

    results["Answer"] = {"status":"ok","content":content}
    return {"trace":trace_id,"checks":results,"final":"ok"}


# -----------------------------
# Gradio Interface
# -----------------------------
import gradio as gr

REFERENCE_CORPUS = [
    "This is an example paper text ...",
    "Another doc with content ..."
]

def run_agent(user_query):
    return answer_pipeline(user_query, REFERENCE_CORPUS)

demo = gr.Interface(
    fn=run_agent,
    inputs=gr.Textbox(lines=4, placeholder="Enter your query here..."),
    outputs="json",
    title="🛡️ Failsafe Agent MCP",
    description="Shows guardrail outcomes across all layers (Input Restriction, Malicious Code, LLM Safety, Plagiarism)."
)

if __name__ == "__main__":
    # CLI demo
    test_queries = {
        "Safe Query": "Explain quantum computing basics",
        "Sensitive Query": "I want to kill myself",
        "Malicious Code": "import os\nos.system('rm -rf /')",
        "Plagiarism": "Echo from gpt-4o-mini: This is an example paper text ...",
        "Oversized Input": "A" * 6000
    }

    print("\n=== Failsafe Agent Demo (CLI) ===\n")
    for label, query in test_queries.items():
        result = answer_pipeline(query, REFERENCE_CORPUS)
        print(f"--- {label} ---")
        print(f"Trace ID: {result['trace']}")
        print("| Check Category       | Status   | Reason/Content |")
        print("|----------------------|----------|----------------|")
        for check, outcome in result["checks"].items():
            reason = outcome.get("reason","")
            if check=="Answer":
                reason = outcome.get("content","")
            print(f"| {check:<20} | {outcome['status']:<8} | {reason[:60]} |")
        print(f"Final Outcome: {result['final']}\n")

    # Launch GUI
    demo.launch()
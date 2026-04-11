"""
Per-document-type chunker (v2).

Differs from html_parser.py's single-strategy splitter:
  - Hierarchical: splits at h2, then sub-splits at h3 inside each h2 block.
  - Per-type SECTION_KEYWORDS, max_tokens, overlap, main/sub heading levels.
  - MAR uses h3/h4 (top-level "Findings" → per-hash sub-chunks).

Pure in-memory: no DB, no S3. Takes (document_type, html) → list[ChunkV2].
"""
import hashlib
import re
from dataclasses import dataclass, field
from typing import Optional

import tiktoken
from bs4 import BeautifulSoup, NavigableString, Tag

ENCODING = tiktoken.get_encoding("cl100k_base")

# Hard ceiling — even protected sections must split beyond this, or embedding will fail.
# OpenAI text-embedding-3 max input is 8191 tokens. Leave headroom.
HARD_MAX_TOKENS = 2500

NOISE_TAGS = ["script", "style", "nav", "footer", "header", "noscript", "form", "aside"]

SKIP_HEADINGS = {
    "please share your thoughts",
    "related advisories",
    "share your thoughts",
    "feedback",
    "disclaimer",
    "disclaimer of endorsement",
    "acknowledgements",
    "acknowledgment",
    "version history",
    "reporting",
    "contact information",
    "document faq",
    "tags",
    "notes",
    "notification",
    "purpose",
}

# Regex patterns (reused)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# ---------------------------------------------------------------------------
# Per-type strategy config
# ---------------------------------------------------------------------------

# Keyword dicts are order-sensitive: specific categories MUST come before
# generic ones. "Summary" is the broadest catch-all, so it goes last.
# A heading matches the FIRST category whose any keyword appears in it (substring).

_JOINT_KEYWORDS = {
    # --- specific technical categories first ---
    "IoC": ["indicator of compromise", "ioc", "indicators", "artifact"],
    "MITRE": ["mitre", "att&ck", "d3fend", "tactics and techniques"],
    "CVE": ["cves exploited", "vulnerabilities exploited", "cves"],
    "Detection": ["yara", "sigma", "validate security", "threat hunting", "hunting guidance", "detection"],
    "Technical Detail": [
        "technical", "ttp", "kill chain", "initial access", "persistence",
        "privilege", "defense evasion", "credential access", "discovery",
        "lateral", "collection", "command and control", "exfiltration",
        "impact", "reconnaissance", "resource development",
        "threat actor activit", "case study",
    ],
    "Lessons": ["lessons learned", "key finding", "noted strength"],
    "Mitigation": ["mitigation", "recommendation", "incident response", "hardening"],
    "Background": ["background", "historical", "actor profile", "group profile", "development of"],
    "Resource": ["resource", "appendix"],
    # --- catch-all for intro/exec content, always last ---
    "Summary": ["executive summary", "at a glance", "introduction", "overview", "summary"],
}

_MAR_KEYWORDS = {
    "Relationship": ["relationship"],  # must precede Summary to beat "Relationship Summary"
    "Findings": ["finding"],
    "Detection": ["yara", "sigma", "detection"],
    "MITRE": ["mitre", "att&ck", "technique"],
    "Recommendation": ["recommend", "mitigation"],
    "Summary": ["executive summary", "at a glance", "introduction", "overview", "summary"],
}

_AR_KEYWORDS = {
    "Malware Metadata": ["metadata"],
    "Malware Delivery": ["delivery"],
    "Malware Functionality": ["functionality", "capabilit"],
    "Detection": ["yara", "sigma", "detection"],
    "MITRE": ["mitre", "att&ck", "technique"],
    "Mitigation": ["mitigation", "incident response", "recommendation"],
    "Appendix": ["appendix"],
    "Summary": ["executive summary", "at a glance", "introduction", "overview", "summary"],
}

_IR_LESSONS_KEYWORDS = {
    **_JOINT_KEYWORDS,
    "Timeline": ["timeline", "key events"],
}

TYPE_STRATEGY: dict[str, dict] = {
    "MAR": {
        "max_tokens": 1400,
        "overlap_tokens": 200,
        "main_level": "h3",
        "sub_level": "h4",
        "keywords": _MAR_KEYWORDS,
        "protect_sections": {"Findings"},  # don't sub-split; keep hash blocks whole
    },
    "ANALYSIS_REPORT": {
        "max_tokens": 1200,
        "overlap_tokens": 150,
        "main_level": "h2",
        "sub_level": "h3",
        "keywords": _AR_KEYWORDS,
        "protect_sections": {"Detection"},  # keep YARA/Sigma together
    },
    "JOINT_CSA": {
        "max_tokens": 1000,
        "overlap_tokens": 150,
        "main_level": "h2",
        "sub_level": "h3",
        "keywords": _JOINT_KEYWORDS,
        "protect_sections": {"IoC", "MITRE", "CVE"},
    },
    "STOPRANSOMWARE": {
        "max_tokens": 1000,
        "overlap_tokens": 150,
        "main_level": "h2",
        "sub_level": "h3",
        "keywords": _JOINT_KEYWORDS,
        "protect_sections": {"IoC", "MITRE", "CVE"},
    },
    "CSA": {
        "max_tokens": 1000,
        "overlap_tokens": 150,
        "main_level": "auto",  # prefer h2, fall back to h3 if <2 h2s
        "sub_level": "h3",
        "keywords": _JOINT_KEYWORDS,
        "protect_sections": {"IoC", "MITRE", "CVE"},
    },
    "IR_LESSONS": {
        "max_tokens": 700,
        "overlap_tokens": 100,
        "main_level": "h2",
        "sub_level": "h3",
        "keywords": _IR_LESSONS_KEYWORDS,
        "protect_sections": {"Lessons", "Timeline"},
    },
}


@dataclass
class ChunkV2:
    advisory_id: str
    chunk_index: int
    section_name: str          # top-level (h2/h3) canonical name
    sub_section: Optional[str]  # raw h3/h4 text, if any
    chunk_text: str
    token_count: int
    content_hash: str
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    mitre_tech_ids: list[str] = field(default_factory=list)

    @property
    def chunk_id(self) -> str:
        return f"{self.advisory_id}_{self.chunk_index:03d}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clean_html(html: str) -> BeautifulSoup:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(NOISE_TAGS):
        tag.decompose()
    main = soup.find("main")
    return main if main else soup


def _count_tokens(text: str) -> int:
    return len(ENCODING.encode(text))


def _split_with_overlap(text: str, max_tokens: int, overlap: int) -> list[tuple[str, int]]:
    """Return list of (text, token_count) pairs. token_count is the slice length, not re-encoded."""
    tokens = ENCODING.encode(text)
    if len(tokens) <= max_tokens:
        return [(text, len(tokens))]
    chunks: list[tuple[str, int]] = []
    start = 0
    while start < len(tokens):
        end = min(start + max_tokens, len(tokens))
        slice_ = tokens[start:end]
        chunks.append((ENCODING.decode(slice_), len(slice_)))
        if end == len(tokens):
            break
        start = end - overlap
    return chunks


def _normalize_section(heading: str, keywords: dict[str, list[str]]) -> str:
    lower = heading.lower()
    for name, kws in keywords.items():
        if any(kw in lower for kw in kws):
            return name
    return "General"


def _extract_ids(text: str) -> tuple[list[str], list[str], list[str]]:
    return (
        sorted({m.upper() for m in CVE_RE.findall(text)}),
        sorted({m.upper() for m in CWE_RE.findall(text)}),
        sorted(set(MITRE_RE.findall(text))),
    )


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _resolve_main_level(main_soup, configured: str) -> str:
    if configured != "auto":
        return configured
    h2s = [h.get_text(strip=True).lower() for h in main_soup.find_all("h2")]
    meaningful = [t for t in h2s if t not in SKIP_HEADINGS]
    return "h2" if len(meaningful) >= 2 else "h3"


# ---------------------------------------------------------------------------
# Hierarchical section extraction
# ---------------------------------------------------------------------------

@dataclass
class _Block:
    """An h2 (or h3-as-main) block, possibly containing sub-sections."""
    heading: str                       # raw heading text
    normalized: str                    # canonical section name
    intro_text: str                    # text before first sub-heading
    sub_blocks: list[tuple[str, str]]  # (sub_heading_text, sub_text)


def _collect_blocks(main_soup, main_level: str, sub_level: str, keywords: dict) -> list[_Block]:
    """
    Walk the soup; every `main_level` heading opens a new _Block.
    Inside a block, every `sub_level` heading opens a new sub-block.
    Text outside any main heading is attached to a synthetic leading "General" block.
    """
    blocks: list[_Block] = [_Block("General", "Summary", "", [])]
    cur_block = blocks[0]
    cur_sub_heading: Optional[str] = None
    cur_sub_parts: list[str] = []
    cur_main_parts: list[str] = []
    skip_current = False

    def flush_sub():
        nonlocal cur_sub_heading, cur_sub_parts
        if cur_sub_heading is not None:
            text = " ".join(cur_sub_parts).strip()
            if text:
                cur_block.sub_blocks.append((cur_sub_heading, text))
            cur_sub_heading = None
            cur_sub_parts = []

    def flush_main_intro():
        nonlocal cur_main_parts
        text = " ".join(cur_main_parts).strip()
        if text:
            cur_block.intro_text = (cur_block.intro_text + " " + text).strip()
        cur_main_parts = []

    def walk(node):
        nonlocal cur_block, cur_sub_heading, cur_sub_parts, cur_main_parts, skip_current
        for elem in node.children:
            if isinstance(elem, NavigableString):
                if skip_current:
                    continue
                t = str(elem).strip()
                if not t:
                    continue
                if cur_sub_heading is not None:
                    cur_sub_parts.append(t)
                else:
                    cur_main_parts.append(t)
                continue

            if not isinstance(elem, Tag):
                continue

            if elem.name == main_level:
                flush_sub()
                flush_main_intro()
                heading_text = elem.get_text(strip=True)
                if heading_text.lower() in SKIP_HEADINGS:
                    skip_current = True
                    cur_block = _Block(heading_text, "SKIP", "", [])
                else:
                    skip_current = False
                    cur_block = _Block(
                        heading=heading_text,
                        normalized=_normalize_section(heading_text, keywords),
                        intro_text="",
                        sub_blocks=[],
                    )
                    blocks.append(cur_block)
                continue

            if elem.name == sub_level and not skip_current:
                flush_sub()
                sub_heading = elem.get_text(strip=True)
                if sub_heading.lower() in SKIP_HEADINGS:
                    cur_sub_heading = None
                    continue
                cur_sub_heading = sub_heading
                cur_sub_parts = []
                continue

            walk(elem)

    walk(main_soup)
    flush_sub()
    flush_main_intro()

    return [b for b in blocks if b.normalized != "SKIP"]


# ---------------------------------------------------------------------------
# Chunk emission
# ---------------------------------------------------------------------------

def chunk_advisory(
    advisory_id: str,
    document_type: str,
    html: str,
) -> list[ChunkV2]:
    strategy = TYPE_STRATEGY.get(document_type or "", TYPE_STRATEGY["CSA"])
    main_level = strategy["main_level"]
    sub_level = strategy["sub_level"]
    keywords = strategy["keywords"]
    max_tokens = strategy["max_tokens"]
    overlap = strategy["overlap_tokens"]
    protect: set[str] = strategy.get("protect_sections", set())

    main_soup = clean_html(html)
    resolved_main = _resolve_main_level(main_soup, main_level)

    blocks = _collect_blocks(main_soup, resolved_main, sub_level, keywords)

    chunks: list[ChunkV2] = []
    idx = 0

    def emit(section: str, sub: Optional[str], text: str):
        nonlocal idx
        text = text.strip()
        if not text:
            return
        # Protected sections: prefer keeping whole, but enforce HARD_MAX fallback.
        if section in protect:
            n_tokens = _count_tokens(text)
            if n_tokens <= HARD_MAX_TOKENS:
                parts = [(text, n_tokens)]
            else:
                parts = _split_with_overlap(text, HARD_MAX_TOKENS, overlap)
        else:
            parts = _split_with_overlap(text, max_tokens, overlap)
        for part, tok_count in parts:
            part = part.strip()
            if not part:
                continue
            cves, cwes, mitres = _extract_ids(part)
            chunks.append(ChunkV2(
                advisory_id=advisory_id,
                chunk_index=idx,
                section_name=section,
                sub_section=sub,
                chunk_text=part,
                token_count=tok_count,
                content_hash=_sha256(part),
                cve_ids=cves,
                cwe_ids=cwes,
                mitre_tech_ids=mitres,
            ))
            idx += 1

    for block in blocks:
        if block.intro_text:
            emit(block.normalized, None, block.intro_text)
        for sub_heading, sub_text in block.sub_blocks:
            emit(block.normalized, sub_heading, sub_text)

    return chunks

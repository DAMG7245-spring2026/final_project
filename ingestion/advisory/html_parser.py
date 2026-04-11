"""
CISA Advisory HTML Parser
Reads raw HTML from S3, splits into section-based chunks,
extracts CVE/CWE/MITRE IDs, and writes to ADVISORY_CHUNKS + updates ADVISORIES.
"""
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

import boto3
import snowflake.connector
import tiktoken
from bs4 import BeautifulSoup, NavigableString
from dotenv import load_dotenv

load_dotenv()

from app.config import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOISE_TAGS = ["script", "style", "nav", "footer", "header", "noscript", "form", "aside"]

# Headings that are pure boilerplate — skip entirely (no chunks generated)
SKIP_HEADINGS = {
    "please share your thoughts",
    "related advisories",
    "share your thoughts",
    "feedback",
    "disclaimer",
    "acknowledgements",
    "acknowledgment",
    "version history",
    "reporting",
    "contact information",
    "document faq",
    "tags",
    "resources",
}

# Headings used only to count "meaningful" h2s for level detection
BOILERPLATE_HEADINGS = SKIP_HEADINGS

SECTION_KEYWORDS: dict[str, list[str]] = {
    "Summary": ["summary", "introduction", "overview", "background", "executive"],
    "Technical Detail": ["technical", "malware", "tactic", "ttp", "mitre", "finding", "appendix", "analysis"],
    "Mitigation": ["mitigation", "recommendation", "action", "incident response", "validate", "control", "remediat"],
    "IoC": ["ioc", "indicator", "hash", "domain", "yara", "artifact"],
    "Detection": ["detection", "hunting", "monitor", "rule", "signature"],
}

MAX_TOKENS = 1000
OVERLAP_TOKENS = 150

# Regex patterns
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Document-type classification patterns
STOPRANSOMWARE_RE = re.compile(r"#?\s*stopransomware", re.IGNORECASE)
IR_LESSONS_RE = re.compile(
    r"lessons learned|incident response engagement|ir engagement",
    re.IGNORECASE,
)
MAR_RE = re.compile(r"\bMAR[-\u2010-\u2015\s]?\d|malware analysis report", re.IGNORECASE)

# Known authoring agencies appearing in joint CSAs — used as a fallback
# signal when _extract_co_authors() finds nothing.
AUTHORING_AGENCY_RE = re.compile(
    r"\b(CISA|FBI|NSA|DHS|DOE|HHS|DoD|MS-ISAC|NCSC(?:-[A-Z]+)?|ACSC|ASD|CCCS|"
    r"ANSSI|BSI|KISA|JPCERT(?:/CC)?|NCA|CERT-NZ|SingCERT|CSE|USSS|USCG|EPA)\b"
)

ENCODING = tiktoken.get_encoding("cl100k_base")


# ---------------------------------------------------------------------------
# Data class
# ---------------------------------------------------------------------------

@dataclass
class Chunk:
    advisory_id: str
    chunk_index: int
    section_name: str
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
# Snowflake helpers
# ---------------------------------------------------------------------------

def _get_snowflake_conn():
    s = get_settings()
    return snowflake.connector.connect(
        account=s.snowflake_account,
        user=s.snowflake_user,
        password=s.snowflake_password,
        database=s.snowflake_database,
        schema=s.snowflake_schema,
        warehouse=s.snowflake_warehouse,
    )


def _get_unprocessed_advisories(conn) -> list[tuple[str, str, str, str]]:
    """Return (advisory_id, s3_raw_path, title, advisory_type) for advisories not yet chunked."""
    cur = conn.cursor()
    cur.execute("""
        SELECT advisory_id, s3_raw_path, title, advisory_type
        FROM advisories
        WHERE advisory_id NOT IN (
            SELECT DISTINCT advisory_id FROM advisory_chunks
        )
        ORDER BY published_date DESC
    """)
    rows = cur.fetchall()
    cur.close()
    return rows


def _insert_chunks(conn, chunks: list["Chunk"]):
    """Insert chunks into ADVISORY_CHUNKS (skip duplicates)."""
    if not chunks:
        return
    sql = """
        INSERT INTO advisory_chunks
            (chunk_id, advisory_id, chunk_index, section_name,
             chunk_text, token_count, content_hash,
             cve_ids, cwe_ids, mitre_tech_ids)
        SELECT %s, %s, %s, %s,
               %s, %s, %s,
               PARSE_JSON(%s)::ARRAY,
               PARSE_JSON(%s)::ARRAY,
               PARSE_JSON(%s)::ARRAY
        WHERE NOT EXISTS (
            SELECT 1 FROM advisory_chunks WHERE chunk_id = %s
        )
    """
    cur = conn.cursor()
    for chunk in chunks:
        cur.execute(sql, (
            chunk.chunk_id, chunk.advisory_id, chunk.chunk_index, chunk.section_name,
            chunk.chunk_text, chunk.token_count, chunk.content_hash,
            json.dumps(chunk.cve_ids), json.dumps(chunk.cwe_ids), json.dumps(chunk.mitre_tech_ids),
            chunk.chunk_id,
        ))
    conn.commit()
    cur.close()


def _update_advisories_metadata(
    conn,
    advisory_id: str,
    chunks: list["Chunk"],
    co_authors: list[str],
    document_type: str,
):
    """Backfill cve_ids_mentioned, mitre_ids_mentioned, co_authors, document_type in ADVISORIES."""
    all_cve = list({cve for c in chunks for cve in c.cve_ids})
    all_mitre = list({m for c in chunks for m in c.mitre_tech_ids})

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE advisories
        SET cve_ids_mentioned   = PARSE_JSON(%s)::ARRAY,
            mitre_ids_mentioned = PARSE_JSON(%s)::ARRAY,
            co_authors          = PARSE_JSON(%s)::ARRAY,
            document_type       = %s
        WHERE advisory_id = %s
        """,
        (
            json.dumps(all_cve),
            json.dumps(all_mitre),
            json.dumps(co_authors),
            document_type,
            advisory_id,
        ),
    )
    conn.commit()
    cur.close()


# ---------------------------------------------------------------------------
# S3 helper
# ---------------------------------------------------------------------------

def _download_html(s3_raw_path: str) -> Optional[str]:
    """Download raw HTML from S3."""
    s = get_settings()
    s3 = boto3.client(
        "s3",
        aws_access_key_id=s.aws_access_key_id,
        aws_secret_access_key=s.aws_secret_access_key,
        region_name=s.aws_region,
    )
    try:
        resp = s3.get_object(Bucket=s.s3_bucket, Key=s3_raw_path)
        return resp["Body"].read().decode("utf-8", errors="replace")
    except Exception as e:
        logger.error(f"Failed to download {s3_raw_path}: {e}")
        return None


# ---------------------------------------------------------------------------
# HTML cleaning
# ---------------------------------------------------------------------------

def _clean_html(html: str) -> BeautifulSoup:
    """Remove noise tags, return the <main> element (or full soup fallback)."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(NOISE_TAGS):
        tag.decompose()
    main = soup.find("main")
    return main if main else soup


# ---------------------------------------------------------------------------
# Section splitting
# ---------------------------------------------------------------------------

def _normalize_section_name(heading: str) -> str:
    """Map heading text → standard section_name."""
    lower = heading.lower()
    for section_name, keywords in SECTION_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return section_name
    return "General"


def _pick_heading_level(main_soup) -> str:
    """Detect whether h2 or h3 should be used as section boundaries."""
    h2_texts = [h.get_text(strip=True).lower() for h in main_soup.find_all("h2")]
    meaningful_h2s = [t for t in h2_texts if t not in BOILERPLATE_HEADINGS]
    return "h2" if len(meaningful_h2s) >= 2 else "h3"


def _split_into_sections(main_soup) -> list[tuple[str, str]]:
    """
    Split content at the chosen heading level (h2 or h3).
    Returns list of (section_name, text).
    """
    heading_tag = _pick_heading_level(main_soup)
    sections: list[tuple[str, str]] = []
    current_name = "General"
    current_parts: list[str] = []

    skip_current = False  # True when current section is boilerplate

    def _walk(node):
        nonlocal current_name, current_parts, skip_current
        for elem in node.children:
            if isinstance(elem, NavigableString):
                if not skip_current:
                    t = str(elem).strip()
                    if t:
                        current_parts.append(t)
            elif hasattr(elem, "name"):
                if elem.name == heading_tag:
                    # Flush previous section (only if not boilerplate)
                    if not skip_current:
                        text = " ".join(current_parts).strip()
                        if text:
                            sections.append((current_name, text))
                    heading_text = elem.get_text(strip=True)
                    current_parts = []
                    if heading_text.lower() in SKIP_HEADINGS:
                        skip_current = True
                    else:
                        skip_current = False
                        current_name = _normalize_section_name(heading_text)
                else:
                    _walk(elem)

    _walk(main_soup)
    # Flush last section
    text = " ".join(current_parts).strip()
    if text:
        sections.append((current_name, text))

    return sections


# ---------------------------------------------------------------------------
# Token helpers + sub-splitting
# ---------------------------------------------------------------------------

def _count_tokens(text: str) -> int:
    return len(ENCODING.encode(text))


def _split_with_overlap(text: str, max_tokens: int, overlap_tokens: int) -> list[str]:
    """Split text into token-limited chunks with overlap."""
    tokens = ENCODING.encode(text)
    if len(tokens) <= max_tokens:
        return [text]

    chunks = []
    start = 0
    while start < len(tokens):
        end = min(start + max_tokens, len(tokens))
        chunks.append(ENCODING.decode(tokens[start:end]))
        if end == len(tokens):
            break
        start = end - overlap_tokens

    return chunks


# ---------------------------------------------------------------------------
# Regex extraction + hashing
# ---------------------------------------------------------------------------

def _extract_ids(text: str) -> tuple[list[str], list[str], list[str]]:
    cve_ids = sorted({m.upper() for m in CVE_RE.findall(text)})
    cwe_ids = sorted({m.upper() for m in CWE_RE.findall(text)})
    mitre_ids = sorted({m for m in MITRE_RE.findall(text)})
    return cve_ids, cwe_ids, mitre_ids


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Co-author extraction
# ---------------------------------------------------------------------------

def _count_authoring_agencies(main_soup) -> int:
    """
    Count distinct authoring agency acronyms in the opening text of the body.
    Used as a fallback when co_authors extraction failed to pick up a joint CSA.
    """
    if main_soup is None:
        return 0
    text = main_soup.get_text(separator=" ", strip=True)[:4000]
    return len(set(AUTHORING_AGENCY_RE.findall(text)))


def _classify_document_type(
    title: str,
    advisory_type: str,
    co_authors: list[str],
    main_soup=None,
) -> str:
    """
    Refine the coarse CISA advisory_type into a finer document_type.

    Returns one of: MAR, ANALYSIS_REPORT, STOPRANSOMWARE, IR_LESSONS, JOINT_CSA, CSA.
    If `main_soup` is provided, uses HTML body as a fallback signal for JOINT_CSA
    when `co_authors` extraction came up empty.
    """
    t = title or ""

    if advisory_type == "analysis_report":
        return "MAR" if MAR_RE.search(t) else "ANALYSIS_REPORT"

    # advisory_type == "cybersecurity_advisory" — disambiguate subtypes
    if STOPRANSOMWARE_RE.search(t):
        return "STOPRANSOMWARE"
    if IR_LESSONS_RE.search(t):
        return "IR_LESSONS"
    if len(co_authors) >= 2:
        return "JOINT_CSA"
    # Fallback: scan body for distinct agency acronyms
    if _count_authoring_agencies(main_soup) >= 2:
        return "JOINT_CSA"
    return "CSA"


def _extract_co_authors(main_soup) -> list[str]:
    """Extract co-author organizations from HTML."""
    text = main_soup.get_text(separator="\n")
    match = re.search(
        r"co[-\s]?authored\s+by[:\s]+(.+?)(?:\n\n|\.\s|\Z)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return []
    raw = match.group(1)
    parts = re.split(r"[,;\n]|\band\b", raw)
    return [p.strip() for p in parts if p.strip() and len(p.strip()) < 120]


# ---------------------------------------------------------------------------
# Main chunking pipeline
# ---------------------------------------------------------------------------

def _parse_html_to_chunks(
    advisory_id: str,
    html: str,
    main_soup=None,
) -> list[Chunk]:
    """HTML string → list of Chunk objects. Accepts pre-cleaned soup to avoid double parse."""
    if main_soup is None:
        main_soup = _clean_html(html)
    sections = _split_into_sections(main_soup)

    chunks: list[Chunk] = []
    chunk_index = 0

    for section_name, section_text in sections:
        sub_texts = _split_with_overlap(section_text, MAX_TOKENS, OVERLAP_TOKENS)
        for sub_text in sub_texts:
            sub_text = sub_text.strip()
            if not sub_text:
                continue
            cve_ids, cwe_ids, mitre_ids = _extract_ids(sub_text)
            chunks.append(Chunk(
                advisory_id=advisory_id,
                chunk_index=chunk_index,
                section_name=section_name,
                chunk_text=sub_text,
                token_count=_count_tokens(sub_text),
                content_hash=_sha256(sub_text),
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                mitre_tech_ids=mitre_ids,
            ))
            chunk_index += 1

    return chunks


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_advisories(limit: int = None) -> int:
    """
    Process all unprocessed advisories: HTML → chunks → DB.

    Args:
        limit: max advisories to process (None = all)

    Returns:
        Number of advisories successfully processed.
    """
    conn = _get_snowflake_conn()
    rows = _get_unprocessed_advisories(conn)

    if limit is not None:
        rows = rows[:limit]

    logger.info(f"Found {len(rows)} unprocessed advisories")
    processed = 0

    for i, (advisory_id, s3_raw_path, title, advisory_type) in enumerate(rows, 1):
        logger.info(f"[{i}/{len(rows)}] Processing {advisory_id}")

        html = _download_html(s3_raw_path)
        if html is None:
            logger.warning(f"Skipping {advisory_id}: S3 download failed")
            continue

        # Clean once, reuse for both chunking and co-author extraction
        main_soup = _clean_html(html)
        chunks = _parse_html_to_chunks(advisory_id, html, main_soup=main_soup)
        if not chunks:
            logger.warning(f"Skipping {advisory_id}: no chunks produced")
            continue

        co_authors = _extract_co_authors(main_soup)
        document_type = _classify_document_type(title, advisory_type, co_authors, main_soup=main_soup)

        try:
            _insert_chunks(conn, chunks)
            _update_advisories_metadata(conn, advisory_id, chunks, co_authors, document_type)
        except Exception as e:
            logger.warning(f"DB error on {advisory_id}, reconnecting: {e}")
            conn = _get_snowflake_conn()
            _insert_chunks(conn, chunks)
            _update_advisories_metadata(conn, advisory_id, chunks, co_authors, document_type)

        logger.info(f"  → {len(chunks)} chunks, document_type={document_type}, co_authors={co_authors}")
        processed += 1

    conn.close()
    logger.info(f"Done. Processed {processed}/{len(rows)} advisories.")
    return processed


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    count = parse_advisories()
    print(f"\nTotal processed: {count}")

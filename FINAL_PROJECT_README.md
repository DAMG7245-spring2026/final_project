# Unstructured Advisory Pipeline

This pipeline ingests **CISA Cybersecurity Advisories** (HTML) and converts them into structured, searchable knowledge — chunks stored in Snowflake with vector embeddings, and knowledge-graph triplets in neo4j.

---


## Prerequisites

| Requirement | Version |
|------------|---------|
| Python | 3.11+ |
| Poetry | 2.2.1 |
| Pydantic | 2.5.3 |
| Docker | 20.10.24 |
| Docker Compose | 2.17.2 |
| Snowflake | — |
| AWS S3 bucket | — |
| AWS EC2 | — |
| OpenAI API key | GPT-4o |
| Neo4j AuraDB instance | — |

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [User Flow](#user-flow)
5. [Prerequisites](#prerequisites)
6. [Environment Setup](#environment-setup)

---

## Overview

The unstructured pipeline has 6 main stages:

| Stage |
|-------|
| **1 — Scrape** |
| **2 — Parse & Chunk** |
| **3 — Embed** |
| **4 — Extract Triplets** |
| **5 — Deduplication Entity** |
| **6 — Relation Inference** |

---

## Architecture

```mermaid
graph TB
    subgraph Sources
        CISA["CISA Website<br/>cisa.gov/cybersecurity-advisories"]
    end

    subgraph Stage1["Stage 1 · Scrape"]
        SCR["scraper.py<br/>HTML downloader"]
    end

    subgraph Storage["Persistent Storage"]
        S3["AWS S3<br/>raw/advisories/{id}.html"]
        SF_ADV["Snowflake<br/>advisories table"]
    end

    subgraph Stage2["Stage 2 · Parse & Chunk"]
        PARSER["<br/>Section splitter + metadata extractor"]
        CHUNKER["<br/>Per-doc-type token-aware chunker"]
        SF_CHK["Snowflake<br/>advisory_chunks table"]
    end

    subgraph Stage3["Stage 3 · Embed"]
        EMB["embed_advisory_chunks.py<br/>Snowflake Cortex EMBED_TEXT_1024()"]
    end

    subgraph Stage4["Stage 4 · LLM Triplet Extraction"]
        KNNR["kNN Retrieval<br/>Top-4 demo chunks"]
        POOL["Snowflake<br/>demonstration_pool<br/>(100 gold triplets)"]
        LLM["OpenAI GPT-4o<br/>ICL Prompt"]
        VAL["Pydantic Validator<br/>Whitelist + Dedup"]
        SF_TRP["Snowflake<br/>extracted_triplets table"]
    end

    subgraph Serving["Serving Layer"]
        BM25["BM25 Index<br/>(in-memory, built at startup)"]
        VEC["Cortex Vector Search<br/>(cosine similarity)"]
        RRF["Hybrid RRF Fusion<br/>alpha=0.4 vector weight"]
        NEO4J["Neo4j AuraDB<br/>Knowledge Graph"]
        API["FastAPI<br/>:8000"]
        UI["Streamlit UI<br/>:8501"]
    end

    CISA --> SCR
    SCR --> S3
    SCR --> SF_ADV
    S3 --> PARSER
    PARSER --> CHUNKER
    CHUNKER --> SF_CHK
    SF_CHK --> EMB
    EMB --> SF_CHK
    SF_CHK --> KNNR
    POOL --> KNNR
    KNNR --> LLM
    LLM --> VAL
    VAL --> SF_TRP
    SF_TRP --> NEO4J
    SF_CHK --> BM25
    SF_CHK --> VEC
    BM25 --> RRF
    VEC --> RRF
    RRF --> API
    NEO4J --> API
    API --> UI
```

---

## User Flow

```mermaid
sequenceDiagram
    actor Analyst
    participant UI as Streamlit UI
    participant API as FastAPI :8000
    participant LLM as LLM Classifier
    participant SF as Snowflake
    participant NEO as Neo4j

    Analyst->>UI: Enter natural language query<br/>"Which malware targets healthcare organizations?"
    UI->>API: POST /query<br/>{ "question": "Which malware targets healthcare organizations?" }

    API->>LLM: Classify route
    Note over LLM: named entity + fact → graph<br/>no entity / advice / detection → text<br/>named entity + full picture → both
    LLM-->>API: { route, reasoning }

    alt route = "text"
        API->>API: BM25 rank (in-memory index)
        API->>SF: CORTEX vector similarity<br/>EMBED_TEXT_1024(question) vs chunk_embedding
        SF-->>API: Top-N vector hits with scores
        API->>API: RRF fusion (α=0.4 vector weight)
        API->>SF: Enrich BM25-only hits<br/>(fetch full chunk rows)
        SF-->>API: Enriched chunks
        API->>LLM: Generate answer from top-10 chunks
        LLM-->>API: answer (400–600 words)
    else route = "graph"
        API->>LLM: Text2Cypher → generate Cypher
        LLM-->>API: Cypher query
        API->>NEO: Run Cypher query
        NEO-->>API: Graph rows
        Note over API,NEO: If graph_row_count=0 → fallback to text route
        API->>LLM: Generate answer from graph rows
        LLM-->>API: answer
    else route = "both"
        par parallel retrieval
            API->>LLM: Text2Cypher → generate Cypher
            API->>API: BM25 rank (in-memory)
            API->>SF: CORTEX vector similarity
        end
        LLM-->>API: Cypher query
        API->>NEO: Run Cypher query
        NEO-->>API: Graph rows
        SF-->>API: Vector hits
        API->>API: RRF fusion + enrich
        API->>LLM: Generate merged answer<br/>from graph rows + chunks
        LLM-->>API: answer
    end

    API-->>UI: QueryResponse<br/>{ answer, route, cypher, graph_results, chunks }
    UI->>Analyst: Show answer + supporting evidence
```

---

## Pipeline Description

### Stage 1 — Scrape

The scraper paginates through the CISA advisory listing at `cisa.gov/news-events/cybersecurity-advisories`, collecting two advisory types: **Analysis Reports** and **Cybersecurity Advisories**. For each new entry it extracts `advisory_id`, title, URL, publish date, and type, then downloads the full HTML page, uploads it to **AWS S3** at `raw/advisories/{advisory_id}.html`, and inserts the metadata into the Snowflake `advisories` table.

### Stage 2 — Parse & Chunk

Raw HTML is retrieved from S3 and cleaned by stripping noise tags (`<script>`, `<style>`, `<nav>`, `<footer>`, etc.). The document is then split at heading boundaries (`h2` / `h3`) into semantic sections. Each section heading is mapped to a **canonical section name** — `Summary`, `Technical Detail`, `Mitigation`, `IoC`, `Detection`, or `General` — based on keyword matching.

Chunking strategy varies by document type: each type has a maximum token budget and a preferred heading level. Sections that exceed the token limit are sub-split with a 100–200 token overlap to preserve context across boundaries.

| Document Type | Max Tokens |
|--------------|-----------|
| MAR | 1400 |
| ANALYSIS_REPORT | 1200 |
| JOINT_CSA | 1000 |
| STOPRANSOMWARE | 1000 |
| CSA | 1000 |
| IR_LESSONS | 700 |

All chunks are written to the Snowflake `advisory_chunks` table.

### Stage 3 — Embed

For every chunk in `advisory_chunks`, the pipeline calls **Snowflake Cortex** `EMBED_TEXT_1024()` (arctic-embed-l-v2.0, 1024 dimensions) and writes the result back to the `chunk_embedding` column. The compute runs entirely inside Snowflake, keeping latency and cost low.

### Stage 4 — Extract Triplets

The goal of this stage is to have an LLM automatically extract structured knowledge from each advisory — specifically, triplets of the form `(subject, relation, object)` that capture "who did what to whom."

Before processing any new report, we use vector similarity to retrieve the 4 most similar reports from a **demonstration pool** of 100 manually annotated advisories, include their example triplets in the prompt, and let the LLM learn from them before answering.

Once the LLM returns its output, three filtering steps are applied:

1. **Relation whitelist** — only 7 relation types are accepted: `uses`, `targets`, `exploits`, `attributed_to`, `affects`, `has_weakness`, `mitigates`. Everything else is rejected.
2. **Vague-term filter** — subject and object cannot be non-specific phrases like "the attacker" or "malicious actors."
3. **Exact deduplication** — if identical triplets appear more than once in the same report, only one copy is kept.

Only triplets that pass all three checks are written to the `extracted_triplets` table in Snowflake.

### Stage 5 — Entity Deduplication

After Stage 4, different reports may refer to the same real-world entity under different names — for example, "APT29", "Cozy Bear", and "APT 29" all refer to the same group. Left unaddressed, these would appear as separate nodes in the knowledge graph.

To fix this, we collect all entity names from the database and convert each into a vector using Snowflake's built-in embedding model. We then compute cosine similarity: any pair scoring above **0.85** is flagged as a potential match.

Each candidate pair is sent to GPT-4o with the question: *"Are these two names the same real-world entity? If so, which name should be the canonical form?"* If GPT-4o confirms a match, all aliases are replaced with the canonical name throughout the database, and an additional round of deduplication removes any triplets that become identical after normalisation.

### Stage 6 — Relation Inference

After storing triplets into Neo4j, we noticed that nodes from the same report are not always connected — for example, a report might mention both that APT29 used Cobalt Strike and that a CVE affects Exchange Server, but never explicitly link those two facts. The result is disconnected subgraphs with no edges between them.

To fill in these missing links, we run a **Union-Find algorithm** on each report's subgraph to identify disconnected components. If only one component exists, the graph is already fully connected and we skip it. For reports with multiple components, we select the highest-degree node from each component as its representative, designate the most central one the **topic entity** (usually the main threat actor), and pair it with all other representatives.

Each pair — along with the report's full text — is sent to GPT-4o: *"Based on this report, what is the relationship between these two entities?"* If a clear relationship exists, GPT-4o returns a triplet; if not, we skip that pair.

### Serving — Query Flow

Users submit a natural language question through the Streamlit UI, which calls `POST /query`. The API first passes the question to an **LLM route classifier** that decides which retrieval strategy to use:

- **text route** — No specific named entity in the question, or the question asks for guidance, mitigation, or detection advice. The API runs **hybrid search** (BM25 in-memory index + Snowflake Cortex vector search, fused with Reciprocal Rank Fusion at α = 0.4) against `advisory_chunks` and feeds the top-10 results to an LLM to generate the final answer.
- **graph route** — The question names a specific entity and asks for a structured fact (e.g. "Which CVEs does Volt Typhoon exploit?"). The API calls **Text2Cypher** to generate a Cypher query, runs it against Neo4j, and synthesises the answer from the graph rows. If the query returns zero rows, the pipeline automatically falls back to the text route.
- **both route** — The question involves a specific entity but also asks for narrative context (detection, mitigation, full picture). The graph and text branches run **in parallel**; the LLM merges both result sets into a single answer.

The endpoint returns a `QueryResponse` containing the answer, the chosen route, optional Cypher, graph rows, and the supporting advisory chunks.

---

## Environment Setup

Minimum required for the unstructured pipeline:

```dotenv
# Snowflake
SNOWFLAKE_ACCOUNT=<org>-<account>
SNOWFLAKE_USER=your_user
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_DATABASE=CTI_PLATFORM_DATABASE
SNOWFLAKE_SCHEMA=PUBLIC
SNOWFLAKE_WAREHOUSE=COMPUTE_WH

# AWS S3 (raw HTML storage)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
S3_BUCKET=your-bucket-name

# OpenAI (Stage 4 triplet extraction)
OPENAI_API_KEY=

# Neo4j (serving layer)
NEO4J_URI=neo4j+s://xxxx.databases.neo4j.io
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=
```

---

## Running Locally

```bash
# Install dependencies
poetry install

# Start Redis
docker run -d --name redis-local -p 6379:6379 redis:7-alpine


# Start the server
poetry run uvicorn app.main:app --reload --port 8000
```

API docs available at `http://localhost:8000/docs`

## Running with Docker

```bash
docker compose -f docker/docker-compose.yml --env-file .env up --build
```

# Cyber Threat Intelligence Platform

WE ATTEST THAT WE HAVEN'T USED ANY OTHER STUDENTS' WORK IN OUR ASSIGNMENT AND ABIDE BY THE POLICIES LISTED IN THE STUDENT HANDBOOK

- Wei-Cheng Tu: 33.3%
- Nisarg Sheth: 33.3%
- Yu-Tzu Li: 33.3%

---

## Links

- Video: https://youtu.be/6Dxqd9D894g
- Website: http://35.93.255.114:8501/
- Google Doc: https://docs.google.com/document/d/1DCMEa1o1iLaozGY0VpRLzGYv_xMwoFTxowT8HaJmbcA
- Google colab: https://codelabs-preview.appspot.com/?file_id=1DCMEa1o1iLaozGY0VpRLzGYv_xMwoFTxowT8HaJmbcA#1

---

## Problem Statement

Cybersecurity analysts face a huge volume of cybersecurity threat reports scattered across different sources. Answering questions like "What could be the effect when attackers use some method to attack the server?" requires manually reading from different reports or references; this process may take hours to find the answer.

## Solution

Our platform, the Cyber Threat Intelligence Platform, automatically ingests both structured and unstructured sources like CISA Cybersecurity Advisories. Using a three-phase LLM pipeline, the platform extracts entity-relationship triplets from unstructured text, deduplicates entities, and infers missing relationships to construct a knowledge graph. Analysts can then query this graph using natural language through a Graph RAG engine, receiving answers that previously required hours of manual reading from different reports or references in under a few seconds.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Running Locally](#running-locally)
4. [Running with Docker](#running-with-docker)
5. [Architecture](#architecture)
6. [User Flow](#user-flow)

---

## Prerequisites

| Requirement           | Version  |
| --------------------- | -------- |
| Python                | 3.11+    |
| Poetry                | 2.2.1    |
| Pydantic              | 2.5.3    |
| Docker                | 20.10.24 |
| Docker Compose        | 2.17.2   |
| Snowflake             | —        |
| AWS S3 bucket         | —        |
| AWS EC2               | —        |
| OpenAI API key        | GPT-4o   |
| Neo4j AuraDB instance | —        |

---

## Environment Setup

Create a `.env` file at the project root with the following variables:

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

API docs available at `http://localhost:8000/docs`.

## Running with Docker

```bash
docker compose -f docker/docker-compose.yml --env-file .env up --build
```

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

### NL Query

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

### Weekly Brief

```mermaid
flowchart TB
    Start(["Fetch target CVEs<br/>GET /weekly-brief"])
    Digest["weekly_digest (pure SQL)<br/>tier-ranked top_cves<br/>+ newly_added_kev"]
    Dedup["Dedup unique CVE IDs<br/>(first-seen wins)"]
    Fanout{{"Orchestrator<br/>asyncio.Semaphore(8)<br/>fan-out"}}

    Start --> Digest --> Dedup --> Fanout

    subgraph Workers["Parallel AI Agent Workers · up to 8 concurrent"]
        direction TB

        subgraph W1["CVE Worker #1"]
            direction TB
            W1Q["build_graph_question()<br/>build_text_question()"]

            subgraph W1NL["Query Layer A · Natural Language Query"]
                W1NL1["Text2Cypher LLM<br/>NL → Cypher"]
                W1NL2["Neo4j graph<br/>rows + answer"]
                W1NL1 --> W1NL2
            end

            subgraph W1HS["Query Layer B · Hybrid Search"]
                W1HS1["BM25<br/>in-memory index"]
                W1HS2["Cortex Vector<br/>cosine similarity"]
                W1HS3["RRF fusion α=0.4<br/>top-10 chunks"]
                W1HS1 --> W1HS3
                W1HS2 --> W1HS3
            end

            W1Q --> W1NL
            W1Q --> W1HS

            W1M["_merge_answers()<br/>→ CveEvidence"]
            W1NL --> W1M
            W1HS --> W1M
        end

        W2["CVE Worker #2<br/>(same structure)"]
        WN["CVE Worker #N<br/>(same structure)"]
    end

    Fanout -. dispatch .-> W1
    Fanout -. dispatch .-> W2
    Fanout -. dispatch .-> WN

    Gather["asyncio.gather<br/>collect all CveEvidence"]
    W1 --> Gather
    W2 --> Gather
    WN --> Gather

    Synth["Synthesis Agent<br/>single LLM call<br/>SYNTHESIS_SYSTEM_PROMPT"]

    Gather --> Synth

    Out(["Markdown brief<br/>## Headline numbers<br/>## Newly exploited<br/>## Most dangerous active threats"])

    Synth --> Out
```

# Weekly CVE Threat-Intel Brief — Pipeline & Architecture

作者：CTI 平台團隊
版本：v1.0（2026-04-22）
範圍：本文檔描述 `/weekly-brief` 端點背後的完整管線，包括資料攝取、
排序邏輯、AI agent 設計、API 層、Docker / Airflow 基建，以及每一層
的設計權衡。

---

## 1. 背景與目標

### 1.1 產品定位

對應 **Option 5 — Cyber Threat Weekly Intelligence Brief Generator**：
一個全自動系統，每週產出一份 CISO 級的威脅情資 brief，內容包含：

- 本週 CVE / KEV 活動量的數字面板
- 本週新進 KEV 的「新聞」區塊
- Tier 1 危險 CVE 的持續威脅區塊

Brief 應具備：
- 真實威脅資訊（named threat actors、ransomware 名、IoC、advisory ID）
- 具體行動建議（版本、端口、設定）
- 足夠的資料溯源（每段敘述可回查到結構化證據）

### 1.2 不是什麼

- **不是** 威脅情資庫（我們只摘要現有情資）
- **不是** 即時 SIEM / SOC 工具
- **不是** 一個會自己「決定」要做什麼的自主 agent

---

## 2. 架構總覽

### 2.1 End-to-end 流程

```
┌───────────────────────────────────────────────────────────────┐
│ 外部資料源（每週拉）                                            │
│   NVD API 2.0 ────────────────────┐                           │
│   CISA KEV feed ──────────────────┤                           │
└───────────────────────────────────┼───────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│ Ingestion 層（Airflow DAG 或 CLI）                            │
│   nvd_weekly_delta_dag  → S3 raw → S3 curated → Snowflake     │
│   kev_weekly_dag        → 直接 MERGE Snowflake                │
└───────────────────────────────────┬───────────────────────────┘
                                    │ MERGE (idempotent)
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│ Data warehouse：Snowflake                                      │
│   cve_records（含 NVD 欄位 + KEV enrichment 欄位）             │
│   kev_pending_fetch（queue）                                   │
└───────────────────────────────────┬───────────────────────────┘
                                    │ pure SQL tier ranking
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│ Ranking 層：app/services/weekly_digest.py                      │
│   ├── top_cves()          tier-ranked danger list              │
│   ├── newly_added_kev()   this-week's news feed                │
│   ├── summary_counts()    headline numbers                     │
│   └── weekly_digest()     one-shot combo                       │
└───────────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│ API 層：GET /weekly-digest                                     │
│   Returns: summary + top_cves + newly_added_kev                │
│   純 SQL 結果，不含 LLM 敘述                                    │
└───────────────────────────────────┬───────────────────────────┘
                                    │ dedup unique CVEs
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│ AI agent 層：app/services/weekly_brief.py                      │
│                                                               │
│  Orchestrator                                                 │
│      │                                                        │
│      ├─ fan out (asyncio.gather + Semaphore(8))               │
│      │                                                        │
│      ▼                                                        │
│  N workers (1 per unique CVE)                                 │
│      │                                                        │
│      └─ rag_router.answer(question, force_route="both")       │
│             │                                                 │
│             ├─ text2cypher (graph rows)                       │
│             └─ hybrid_search (advisory chunks)                │
│                                                               │
│  Synthesizer                                                  │
│      │                                                        │
│      └─ LLM call (structured 3-section markdown)              │
└───────────────────────────────────┬───────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────┐
│ API 層：GET /weekly-brief                                      │
│   Returns: markdown + evidence[] + tokens + cost               │
└───────────────────────────────────────────────────────────────┘
```

### 2.2 對應 Anthropic「Building effective agents」分類

| 層 | 對應模式 |
|---|---|
| Ranking（SQL tier） | Workflow: prompt chaining（固定步驟）|
| AI agent（fan-out + synthesize）| Workflow: orchestrator-workers |
| 整體 | Composed workflow（不是 autonomous agent）|

**刻意選擇 workflow 而非 agent**：週報任務本身 predictable、有固定輸入形狀、
不需要 LLM 動態決定步驟數。用 agent 會增加成本、延遲、失敗面與 debug 難度，
沒有對應 upside。

---

## 3. Scope 決策：CVE-only

### 3.1 原本的六資料源願景

Option 5 最初構想含六個資料源：NVD、KEV、ATT&CK、CISA Advisory、OTX、
加上 knowledge graph cross-reference。

### 3.2 MVP scope 縮到只有 CVE（NVD + KEV）

**理由**：
1. 產出品質可以用一個資料源驗證；加更多來源前先看基本盤
2. Complexity 線性於資料源數；三源起跳會指數化 debug 成本
3. `cve_records` 一張表就含 KEV 欄位 + CVSS + has_exploit_ref，訊號密度夠

### 3.3 Graph / Advisory 沒被排除

**注意：scope 決策只影響 trigger list 的來源**，不影響 RAG enrichment。
Neo4j 圖譜裡本來就有 CVE ↔ Actor ↔ Malware ↔ Technique 的連結，
`advisory_chunks` 也已經 chunked 好。每個被選中的 CVE 仍透過 `rag_router`
到這些資料源拉 evidence。

---

## 4. 資料攝取層（Ingestion）

### 4.1 NVD Weekly Delta

**來源**：NVD REST API 2.0 的 `lastModStartDate` / `lastModEndDate` query

**路徑**：
```
NVD API → S3 raw (NDJSON) → S3 curated (normalized) → Snowflake MERGE
```

**檔案**：
- `ingestion/nvd/pipeline.py` — 底層函式（`sync_delta`、`fetch_delta_to_raw_file` 等）
- `airflow/dags/nvd_weekly_delta_dag.py` — 排程 `0 5 * * 0`（週日 05:00 UTC）
- `scripts/nvd_ingest.py` — 同功能 CLI 版本

**關鍵設計**：
- Window 來自 Airflow 的 `data_interval_start/end`，半開區間；backfill 自動對齊
- S3 路徑使用 ISO 週號：`nvd/weekly/raw/2026-W17.jsonl`
- Snowflake `MERGE ... ON cve_id` 冪等，安全重跑

### 4.2 KEV Weekly Sync

**來源**：CISA KEV feed（完整 JSON snapshot）

**路徑**：
```
CISA feed (HTTP GET) → dedupe by cve_id → temp stage → COPY → MERGE cve_records
```

**檔案**：
- `ingestion/kev/enricher.py` — `run_kev_sync()` 做完整 fetch + stage + MERGE
- `airflow/dags/kev_weekly_dag.py` — 排程 `30 5 * * 0`（NVD 後 30 分）
- `scripts/kev_ingest.py` — CLI 版本

**關鍵設計**：
- KEV feed 是完整 snapshot（不是 diff），MERGE 冪等
- CVE 還沒在 `cve_records` 的 KEV 條目塞進 `kev_pending_fetch` queue，下次 NVD
  sync 補齊
- Bulk path（PUT + COPY）+ fallback path（executemany INSERT）—— 小規模會
  fallback，大規模走 bulk

### 4.3 為什麼 NVD 用三層 S3 但 KEV 直接 Snowflake

| 面向 | NVD | KEV |
|---|---|---|
| 來源體量 | 每週可達 50K+ CVE（bulk re-analysis 時）| 固定 ~1500 筆 snapshot |
| Transform 成本 | 高（每筆要抽 CVSS v2/v3/v3.1/v4.0 並 normalize）| 低（flat KV mapping）|
| 需要 audit | 是（policy 上）| 否 |

S3 中間層讓 NVD transform 可以獨立重跑、可以查 raw。KEV 太小不值得這個 overhead。

---

## 5. Ranking 層：Pure SQL

### 5.1 設計哲學

**排序決策全部放在 SQL，LLM 完全不介入**。原因：

1. **確定性**：SQL tier 規則可以回溯、可測試、可 version control
2. **成本**：排序 13 筆 CVE 不花錢；若用 LLM ranking，每週至少多一次 call
3. **速度**：Snowflake 單表查詢 <1 秒；LLM classifier 5-10 秒
4. **可審計**：規則改變等於 SQL 變，git diff 一目瞭然

### 5.2 Tier 規則

| Tier | 條件 | 語意 |
|---|---|---|
| 1 | `is_kev = TRUE AND kev_ransomware_use = 'Known'` | 最強訊號：實際被 ransomware 利用 |
| 2 | `is_kev = TRUE AND kev_date_added IN window` | 本週新進 KEV（新鮮） |
| 3 | `has_exploit_ref = TRUE AND cvss_score >= 9.0` | 有公開 exploit 的 critical CVE |
| 4 | `cvss_severity = 'CRITICAL' AND confidentiality_impact = 'HIGH'` | 最慘烈 severity |
| 5 | 其他（預設排除）| 尾部噪音 |

Tier 內排序：
```
tier ASC
→ kev_date_added DESC NULLS LAST     ← 新 KEV 浮上來
→ cvss_score DESC
→ exploitability_score DESC
→ impact_score DESC
→ last_modified DESC
```

**`kev_date_added DESC` 當 Tier 內第一鍵** 是刻意的：Tier 1 池裡可能有 20+
筆（ransomware KEV 池），如果只用 CVSS 當主鍵，會被 2010 年的 Adobe / Flash
古董占滿。`kev_date_added` 讓最近被標 KEV 的 CVE 浮上來，更貼近週報「新聞」
需求。

### 5.3 Newly-added-KEV 獨立 query

`top_cves` 的 limit 可能被 Tier 1 池吃光，本週新進 KEV（Tier 2）若本來就少
於限額，會整段消失。

**解法**：`newly_added_kev()` 跑**獨立 SQL**，只查 `is_kev = TRUE AND kev_date_added IN window`，
不跟 top_cves 搶位置。回傳包含在 `weekly_digest()` dict 的 `newly_added_kev` 欄位。

這個分離讓 brief 有兩塊獨立素材：
- `top_cves` = 本週最危險的 N 筆
- `newly_added_kev` = 本週 KEV 新進的 M 筆

兩者可能重疊；orchestrator 層透過 `overlap_ids` 處理。

---

## 6. AI Agent 層：Orchestrator-Workers

### 6.1 架構選擇

依 Anthropic 原文判斷，四種 workflow 中：

| 候選 | 適合性 |
|---|---|
| Single LLM call | 勉強可用，但 13 個 CVE 擠進一個 prompt 會讓每筆敘述被壓縮 |
| Prompt chaining | Overkill；步驟間沒 gate 需要 |
| Parallelization (sectioning) | 正是我們要的（per-CVE evidence 彼此獨立）|
| **Orchestrator-workers** | **最適合** —— worker 可以動態 decide 用 graph 還是 text，每個 CVE 拿到客製 evidence |

最終採用 **orchestrator-workers**：

```
Orchestrator:
  1. 拿 digest dict
  2. 合併 top_cves + newly_added_kev，dedup by cve_id
  3. fan-out N 個 worker（bounded at 8 concurrent）
  4. 收齊 evidence pack 後呼叫 synthesizer
  5. 回傳 WeeklyBrief

Worker:
  輸入：WeeklyCve row
  動作：rag_router.answer(build_question(cve), force_route="both")
  輸出：CveEvidence（結構化 row + LLM 寫好的 evidence 段落）

Synthesizer:
  輸入：summary + top_cves + newly_added_kev + evidence[]
  動作：單一 LLM call，生成 3 section markdown
  輸出：markdown 字串 + token/cost
```

### 6.2 為什麼 worker 共用 `rag_router`

你的 `rag_router.answer(force_route="both")` 已經內建：
- 平行 graph (`text2cypher`) + text (`hybrid_search`)
- 結果合併成一段 LLM-generated answer
- 完整 logging / budget tracking

我們只是**把它當一個 tool**：週報 orchestrator 呼叫它，不重造輪子。這是
Anthropic 原文強調的「**tool design**」—— rag_router 已經是一個設計良好的
工具，orchestrator 只需知道「把 CVE 問題丟進去，拿到 evidence」。

### 6.3 為什麼 `force_route="both"`

原本 `rag_router` 有三條路：
- `"graph"`：named entity + 結構化問題
- `"text"`：guidance / mitigation / detection
- `"both"`：混合

我們刻意 `force_route="both"` 跳過 classifier，因為：
1. **節省一次 LLM call**（classifier 本身要錢）
2. **對 CVE 問「全貌」永遠適用 both**：我們的 question template 同時問 actor（graph 擅長）+ mitigation（text 擅長），不需要 classifier 判斷
3. **可預期性**：每個 CVE 用同一個 route，log 容易 slice

### 6.4 為什麼不用 LangChain / LangGraph

**評估結果：不用**。

| 框架 | 對本管線的價值 | 決策 |
|---|---|---|
| LangChain | 零 —— `LLMRouter` / `RAGRouterService` 已經填好 |  不用 |
| LangGraph | 零 —— 流程是固定 2-step DAG，無條件分支、無迴圈、無 human-in-the-loop | 不用 |
| MCP server | 非零，但**跟 brief 正交** —— MCP 是把 CTI 平台變 tool server 的另一條路 | 分開做 |

框架的甜區在「初期原型、需要很多預置 chain / retriever」。我們已經過了
這階段：每個 service 都是自寫的、prompt 都是手調的、tool 都是實作好的。
加框架等於用它的介面重寫一遍，Anthropic 原文的警語直接命中：

> "frameworks create extra layers of abstraction that can obscure the
> underlying prompts and responses, making them harder to debug."

---

## 7. 問題生成：Template + Metadata 注入（Option D）

### 7.1 選項比較

| 選項 | LLM call | 品質 | 決定性 |
|---|---|---|---|
| A. 固定 template（泛用） | 0 | 低 | 高 |
| B. LLM-generated question | +N 次 | 最高 | 低（LLM 不穩）|
| C. Raw NVD description | 0 | 爛（description 技術細節太多，graph 查不到）| 高 |
| **D. Template + metadata 注入** | 0 | 中高 | 高 |

**採用 D**。

### 7.2 具體實作

```python
def build_question(cve: WeeklyCve) -> str:
    vendor = cve.kev_vendor_project or "unknown vendor"
    product = cve.kev_product or "the affected product"
    ransomware_hint = (
        "This CVE is linked to known ransomware campaigns. "
        if cve.kev_ransomware_use == "Known" else ""
    )
    kev_hint = (
        f"It was added to the CISA KEV catalog on {cve.kev_date_added}. "
        if cve.is_kev and cve.kev_date_added else ""
    )
    return (
        f"{cve.cve_id} affects {vendor} {product}. "
        f"{ransomware_hint}{kev_hint}"
        "What threat actors, malware families, and campaigns have "
        "exploited this vulnerability? Include detection indicators "
        "and mitigation guidance from available advisories."
    )
```

### 7.3 為什麼 D 好

1. **text2cypher 有 entity hint**：`CVE-2023-27351` 明確，Cypher 抓得到
2. **hybrid_search 有強 BM25 term**：`PaperCut`、`NG/MF` 是不常見 token
3. **answer LLM 有 threat-intel framing**：不會被 description 的內部技術
   細節帶偏
4. **零 extra call**，零 token 浪費
5. **deterministic**：同一週同一 CVE 永遠是同樣的 question → log 可重現

### 7.4 什麼情況該改 B

三個條件都滿足時考慮升級：
1. 非 KEV CVE（`kev_vendor_project` / `kev_product` 都 NULL）越來越多
2. 想支援 actor-report 之類非 CVE scope（template 難寫）
3. 有預算加 guardrail 驗證 LLM 生成的 question

**現在都不成立**。

---

## 8. 並發策略：asyncio + Semaphore

### 8.1 Thread vs asyncio

`rag_router.answer()` 是同步函式，內部又用 `ThreadPoolExecutor(max_workers=2)`
跑 graph + text。兩個選項：

| 選項 | 優點 | 缺點 |
|---|---|---|
| ThreadPoolExecutor（外層）| 簡單 | FastAPI event loop 被 block |
| **asyncio + to_thread（外層）** | Event loop 不 block；cancellation 乾淨；整合 FastAPI | 底下其實也是 thread，沒比較快 |

**採用 asyncio**。效能相同（底層同一個 thread pool），但語法乾淨、配合
FastAPI 自然、之後要加 SSE / cancellation 容易。

### 8.2 具體實作

```python
async def _gather_cve_evidence(cves: list[WeeklyCve]) -> list[CveEvidence]:
    seen: dict[str, WeeklyCve] = {}
    for c in cves:
        seen.setdefault(c.cve_id, c)   # first-seen-wins dedup
    unique = list(seen.values())

    sem = asyncio.Semaphore(MAX_CONCURRENT_WORKERS)  # = 8

    async def _bounded(cve: WeeklyCve) -> CveEvidence:
        async with sem:
            return await asyncio.to_thread(_invoke_rag, cve)

    return await asyncio.gather(*(_bounded(c) for c in unique))
```

### 8.3 為什麼 Semaphore(8)

- `asyncio.to_thread` 預設 executor 有 `min(32, cpu_count+4)` worker
- 13 個 CVE 全部同時發射會撞三面牆：Anthropic API rate limit、
  Snowflake connection pool、text2cypher 內層更多 thread
- 8 是 rate limit 友善又不拖慢的甜蜜點

### 8.4 Dedup 放在哪

Dedup 在 orchestrator 層，**早於 fan-out**。例子：
- `top_cves = [A, B, C]`，`newly_added_kev = [B, D]`
- 合併：`[A, B, C, B, D]`
- Dedup（first-seen）：`[A, B, C, D]`
- **4 個 worker，不是 5 個**

同時傳給 synthesizer 一個 `overlap_ids = {B}` 集合，讓它在 markdown 裡
把 B 合併敘述、不重複。

---

## 9. Synthesis Prompt：結構化 3-section + 硬規則

### 9.1 結構

```
## Headline numbers
  （表格 + 3-5 句 narrative + cross-CVE pattern + 週一頭條）

## This week's newly exploited
  （每個 newly-added CVE 一段，4-7 句）

## Most dangerous active threats
  （每個 top CVE 若不在 overlap_ids，一段 3-5 句）
```

### 9.2 硬規則（Hard rules）

- Cite CVE IDs verbatim
- Numbers from input exactly（不准估算、四捨五入）
- ISO date format
- **Never fabricate** actor/campaign/IoC —— 沒有就寫 "no named actor in available advisories"
- Iterate **every** top CVE，漏掉要能被讀者 audit 出來
- One paragraph per CVE（兩個 CVE 不能合段，即使同 vendor）
- Fallback line 只在 every top CVE 在 overlap_ids 時才能用

### 9.3 Prompt 演化紀錄

這個 prompt 經歷至少 3 次迭代：

| 版本 | 問題 | 修法 |
|---|---|---|
| v1 | "Most dangerous" 只寫 1-2 句，太短 | 每段拉到 3-5 句 |
| v2 | LLM 漏掉 8 個 top CVE 直接用 fallback | 加 "iterate every ... never drop" 硬規則 + `overlap_ids` 明確指示 |
| v3（現行）| Cisco 兩支合成一段 | 加 "one paragraph per CVE ... no merging" |

每次改都在 commit message / docstring 留理由，避免未來 regression。

---

## 10. API 設計

### 10.1 兩層端點

```
GET /weekly-digest       純 SQL 結果（structured input, no LLM）
GET /weekly-brief        完整 pipeline（結構化 + markdown）
```

### 10.2 為什麼分兩層

1. **Debug 用**：只要 tier 排序怪，打 `/weekly-digest` 快速定位
2. **便宜測試**：`/weekly-digest` 零成本、<1 秒；`/weekly-brief` $0.03、
   20-40 秒
3. **Evidence pack 可重用**：同樣的 digest 可以餵不同 orchestrator
   （未來若做 Slack bot / email digest 可以共用）
4. **符合 Anthropic「transparency」原則**：讓呼叫者看得到 LLM 輸入，
   不是黑箱

### 10.3 Query 參數

| 參數 | 預設 | 說明 |
|---|---|---|
| `window_start` | `window_end - 7d` | ISO date，半開區間起點 |
| `window_end` | today() | ISO date，半開區間終點 |
| `limit` | 10 | top_cves 筆數 |
| `max_tier` | 4 | 最高 tier 編號（5 包括尾部）|
| `newly_added_limit` | 5 | newly_added_kev 筆數 |

### 10.4 回傳 schema

**`WeeklyDigestResponse`**:
```
{ summary, top_cves, newly_added_kev }
```

**`WeeklyBrief`**（包含所有 digest 欄位 + 4 個新欄位）:
```
{
  ...digest fields,
  markdown,                           # 最終 brief
  generated_at,
  evidence,                           # 每個 unique CVE 一筆
  worker_count,
  synthesis_prompt_tokens,
  synthesis_completion_tokens,
  synthesis_cost_usd,
}
```

所有 evidence 含 `route_reasoning`、`graph_row_count`、`chunk_count`、
`fallback_triggered` —— 讀者可以完整 audit。

---

## 11. 基建：Docker + Airflow

### 11.1 Docker stack

```
docker/
├── Dockerfile                    # FastAPI app (python:3.11-slim + poetry)
├── Dockerfile.streamlit          # Streamlit CTI console
├── airflow/
│   ├── Dockerfile                # apache/airflow:2.8.3-python3.11
│   └── requirements-dag-runtime.txt  # snowflake/pydantic/httpx/boto3
├── docker-compose.yml            # api + streamlit + redis
└── docker-compose.airflow.yml    # postgres + airflow-init/scheduler/webserver
```

### 11.2 關鍵設計

- **API 和 Airflow stack 完全獨立**：API 讀 Snowflake；Airflow 寫
  Snowflake。沒共享 docker network。
- **Airflow DAGs 用 bind-mount**（`..:/opt/project`）：本地開發改 code
  即時生效。雲端部署改成 `COPY . /opt/project` 把 code 烤進 image。
- **`requirements-dag-runtime.txt` 刻意不含 `neo4j` / `redis`**：DAG 只
  碰 Snowflake，裝 driver 會肥 image。但這產生一個 `app/services/__init__.py`
  急切 import 的問題（見 12.3）。

### 11.3 `.dockerignore`

加了完整的 `.dockerignore`：排除 `.env`、`.venv`、`data/`、`__pycache__`、
`tests/`、`doc/` 等。避免：
1. 秘密烤進 image layer
2. Build context 肥大（`.venv` 可能 GB 級）

---

## 12. 關鍵 Trade-off 分析

### 12.1 SQL 排序 vs LLM 排序

**選 SQL**：

| 面向 | SQL | LLM |
|---|---|---|
| 成本 | 0 | 每次 $0.01 |
| 速度 | <1s | 5-10s |
| 可測 | Unit test 易 | 難（LLM 不穩）|
| 可審 | git diff | prompt 黑箱 |
| 彈性 | 低 | 高 |

排序規則很結構化（布林 + 數值比較），沒有「LLM 才能判斷」的必要。

### 12.2 Orchestrator-workers vs Single call

**選 orchestrator-workers**：

| 面向 | Single call | Orchestrator-workers |
|---|---|---|
| LLM 呼叫數 | 1 | N+1 (13-14) |
| 成本 | $0.02 | $0.03-0.05 |
| 時間 | 5-10s | 20-40s（主要受限 rag_router 內部）|
| 每 CVE evidence 品質 | 低（擠同一個 prompt）| 高（專屬 context）|
| 失敗隔離 | 整個 brief 失敗 | 單一 CVE 失敗可降級 |

成本只多 50%，但 evidence 品質差異很大（看 PaperCut 段能寫出 Bl00dy
Ransomware Gang / Cobalt Strike Beacons / IoC domains 就是證據）。

### 12.3 Lazy import vs Fat runtime image

**採 lazy import**。

原本 `app/services/__init__.py` 急切 import 所有子模組，結果 Airflow DAG
在 container 裡跑 `from app.services.snowflake import get_snowflake_service`
時會觸發 `__init__.py` 連帶 import `neo4j_service` → `ModuleNotFoundError: neo4j`。

解法 A：把 neo4j / redis 加到 DAG runtime image
解法 B（採用）：`app/services/__init__.py` 改 PEP 562 `__getattr__`
              lazy load

解法 B 更好的原因：
1. Airflow image 保持瘦
2. 符合 Python 單一職責：要哪個 service 才 import
3. 公開 API 不變，`from app.services import get_snowflake_service` 照用
4. 雲端部署也有好處（ECS task 只載它要的 driver）

### 12.4 Docker bind-mount vs COPY

|  | Bind-mount | COPY |
|---|---|---|
| 本地開發迭代 | 改 code 即時 | 要 rebuild |
| 雲端部署 | 不適用（container 沒 repo）| 必須 |
| Layer cache | 無（code 不在 layer）| Code 變就 invalidate |

**現狀**：API 用 COPY（雲端 ready）、Airflow 用 bind-mount（本地快）。
雲端部署時複製一份 Airflow Dockerfile 改成 COPY 即可。

### 12.5 asyncio.Semaphore vs ThreadPoolExecutor(max_workers=8)

效果**完全相同**（都 bounded 並發），選 asyncio 的理由是**非效能的**：

1. FastAPI event loop 不被 block
2. Cancellation 自然（`asyncio.wait_for` / task.cancel）
3. 之後加 SSE streaming 容易
4. 跟 FastAPI async endpoint 互通

### 12.6 `force_route="both"` vs router classifier

**選 force "both"**，因為：

1. CVE 問題穩定適合 both（既要 actor 也要 mitigation）
2. 省一次 classifier call（13 CVE × $0.001 = $0.013）
3. Log 裡每筆都有相同 route，slice 容易
4. 不需要 debug classifier 偶爾選錯

代價：**少數** CVE 可能只有 graph 或只有 advisory 資料，用 both 會有一邊空
返回。但這對 answer LLM 不是問題（它會處理空 evidence）。

### 12.7 evidence cache：不做

MVP 刻意不加 cache。理由：

1. KEV status 會變（剛進 / 剛出 KEV）
2. Graph 會更新（graph_sync 每週跑）
3. Stale cache 的風險 > 省錢的收益（每週跑一次 $0.03）

如果之後 brief 要 on-demand（例如 Slack bot 每小時重問），再加 `(cve_id,
window_start, graph_last_synced_at)` 當 cache key。

---

## 13. 已知限制與失效模式

### 13.1 RAG evidence 混 CVE

觀察：Cisco CVE-2026-20133 的 RAG evidence 把**別的 Cisco CVE 的 RCE
描述**塞進答案（實際 CVE 只是讀檔）。

根因：`hybrid_search` 的 top-10 chunks 可能來自相近 advisory，LLM 沒
明確 filter「只保留這個 CVE 的 chunk」。

影響：Synthesis 忠實傳遞 RAG 的錯，brief 寫出誇大的敘述。

**目前不修**。修法（未來）：
- 在 `build_question` 加「focus on exactly this CVE ID」軟約束
- `hybrid_search` 支援 `cve_ids` 硬過濾（但要小心 advisory chunk 可能不含 CVE metadata）
- Evaluator-optimizer：critic LLM 檢查「brief 敘述的 fact 是否可在 evidence 中找到」

### 13.2 Graph 目前對本 brief 貢獻為 0

觀察：所有 evidence pack 的 `graph_row_count = 0`。

根因（待診斷）：
1. 本週選中的 CVE 在 Neo4j 真的沒 actor / malware edge
2. `text2cypher` 生成的 Cypher 不匹配 graph schema
3. `graph_sync` 還沒把 KEV ransomware 相關 edge 推進 Neo4j

影響：Brief 完全靠 advisory 撐場。幸好 advisory 密度夠，品質沒爛。

**診斷方法**：Neo4j Browser 跑
```cypher
MATCH (c {cve_id: 'CVE-2023-27351'}) RETURN c
```
如果有節點沒 edge → 補 graph_sync；如果整個查不到 → 檢查 ingestion。

### 13.3 Budget / rate limit

- 每 brief 約 $0.03-0.05，週跑一次 = 年 $2
- 若 on-demand 端點被狂打，Anthropic API rate limit 會撞
- 緩解：端點加 Redis rate limit；或引入 cache

### 13.4 Prompt sensitivity

Synthesis prompt 的 iteration 規則對 LLM 很敏感。v1 → v3 每次都發現偷懶
行為。Regression 風險：改 prompt 時要有 smoke test（現在靠手動比對）。

**未來**：寫一個 eval harness，給 prompt 餵 fixture digest 跑 10 次，
檢查「every top CVE appears in exactly one section」。

---

## 14. 檔案結構

```
app/
├── services/
│   ├── __init__.py                  # lazy loading (PEP 562)
│   ├── weekly_digest.py             # tier-ranked SQL
│   ├── weekly_brief.py              # orchestrator-workers agent
│   ├── rag_router.py                # graph + text RAG（既有）
│   ├── llm_router.py                # LiteLLM wrapper with budget（既有）
│   ├── snowflake.py                 # connection + cursor（既有）
│   └── ...
├── routers/
│   ├── weekly_digest.py             # GET /weekly-digest
│   ├── weekly_brief.py              # GET /weekly-brief
│   └── ...
└── main.py                          # FastAPI app factory

ingestion/
├── nvd/pipeline.py                  # NVD fetch/transform/load（既有）
└── kev/enricher.py                  # KEV sync（既有）

airflow/dags/
├── lib/nvd_months.py                # 週批次 helper
├── nvd_weekly_delta_dag.py          # 新增
├── kev_weekly_dag.py                # 新增
├── nvd_fetch_dag.py                 # 歷史 backfill（既有）
├── nvd_transform_dag.py             # 歷史 backfill（既有）
├── nvd_load_dag.py                  # 歷史 backfill（既有）
└── attack_weekly_dag.py             # ATT&CK（既有）

docker/
├── Dockerfile                       # FastAPI image
├── Dockerfile.streamlit             # Streamlit image
├── airflow/
│   ├── Dockerfile                   # Airflow image
│   └── requirements-dag-runtime.txt
├── docker-compose.yml               # api + streamlit + redis
└── docker-compose.airflow.yml       # postgres + airflow

scripts/
├── nvd_ingest.py                    # NVD CLI（既有）
└── kev_ingest.py                    # KEV CLI（既有）

.dockerignore                        # 新增
```

---

## 15. 成本與性能 benchmark

量測條件：Sonnet 4.6（OpenAI gpt-4o 等效，視 `llm_model_*` 設定）。

| 指標 | 數值 |
|---|---|
| `/weekly-digest` latency | < 1 秒 |
| `/weekly-digest` 成本 | $0（純 SQL）|
| `/weekly-brief` latency (13 CVE) | 20-40 秒 |
| `/weekly-brief` latency (5 CVE) | 10-20 秒 |
| `/weekly-brief` 成本 (13 CVE) | $0.03-0.05 |
| `/weekly-brief` synthesis prompt tokens | ~8K（5 CVE）, ~15K（13 CVE）|
| `/weekly-brief` synthesis completion tokens | 400-800（3 段 markdown）|
| NVD weekly sync（7 天 delta）| 1-3 分鐘 |
| KEV weekly sync（1577 筆 snapshot）| 20-30 秒 |

年化成本（每週一 brief）：**$2-3 / 年**。

---

## 16. 未來延伸

### 16.1 短期（<1 週工作量）

| 項目 | 預估 |
|---|---|
| 每週一自動寄 Slack / email 的 Airflow DAG | 2-3 小時 |
| `/weekly-brief/cached`：Redis 24-h cache | 1 小時 |
| Per-CVE RAG cache（`cve_id` + graph snapshot hash）| 2 小時 |
| 修 Airflow DAG 的 lazy import 後續驗證 | 30 分 |

### 16.2 中期（1-2 週）

| 項目 | 預估 |
|---|---|
| Evaluator-optimizer loop（critic LLM）| 3-5 天 |
| 診斷並修 graph_row_count=0 問題 | 2-3 天 |
| 擴充 scope 到 ATT&CK diff | 1 週 |
| MCP server 暴露 `/weekly-brief` 給 Claude Desktop | 2-3 天 |

### 16.3 長期（月級）

| 項目 | 備註 |
|---|---|
| 雲端部署（MWAA + Cloud Run）| 視需求 |
| Advisory ingestion 改雲端（s3 selectors）| 放大資料源 |
| Multi-tenant 版本（per-customer brief）| 商品化 |
| Human-in-the-loop checkpoint（CISO 核可流程）| 此時才考慮 LangGraph |

---

## 17. Anthropic 原則對照

對照 Anthropic 〈Building effective agents〉三大原則：

### 17.1 Maintain simplicity

- ✅ 沒用 LangChain / LangGraph / 任何 framework
- ✅ Orchestrator = 1 個函式、workers = 1 個函式、synthesizer = 1 個函式
- ✅ SQL 排序取代 LLM 排序
- ✅ 問題生成用 template，不是 LLM

### 17.2 Prioritize transparency

- ✅ `/weekly-digest` 顯露所有 LLM 輸入
- ✅ `WeeklyBrief` 回傳 `evidence[]`、`worker_count`、token/cost
- ✅ 每個 RAG worker 的 `route` / `route_reasoning` / `graph_row_count` /
  `chunk_count` 都可 audit
- ✅ Snowflake MERGE 都保留 `ingested_at` 時間戳

### 17.3 Carefully craft ACI

- ✅ Question template 針對 `rag_router` 的輸入形狀設計
- ✅ Synthesis prompt 用 markdown 結構契約 + 硬規則
- ✅ Pydantic schema 在每層 boundary 驗證

---

## 附錄 A：依賴關係圖

```
FastAPI /weekly-brief
  │
  ├── app.services.weekly_brief.generate_weekly_brief
  │     │
  │     ├── app.services.weekly_digest.weekly_digest
  │     │     │
  │     │     └── app.services.snowflake.get_snowflake_service
  │     │
  │     ├── app.services.rag_router.get_rag_router_service
  │     │     │
  │     │     ├── app.services.text2cypher.get_text2cypher_service
  │     │     │     └── app.services.neo4j_service + llm_router
  │     │     ├── app.services.hybrid_search.hybrid_search
  │     │     │     ├── app.services.bm25_index
  │     │     │     └── app.services.vector_search
  │     │     └── app.services.llm_router (answer generation)
  │     │
  │     └── app.services.llm_router (synthesis)
  │
  └── pydantic models: WeeklyBrief / CveEvidence / WeeklyCve / WeeklyDigestSummary
```

## 附錄 B：文件歷程

- v1.0（2026-04-22）：初版。涵蓋 ingestion → ranking → agent → API 完整管線；
  記錄 3 次 prompt iteration；列出已知限制與未來延伸。

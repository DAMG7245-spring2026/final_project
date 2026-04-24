# VectorDB Retrieval Evaluation Report
_Generated 2026-04-20T03:24:18+00:00_

## 1. Setup
- Golden set size: **125**
- Retriever configs: `vector_only`, `bm25_only`, `hybrid@0.2`, `hybrid@0.3`, `hybrid@0.5`, `hybrid@0.7`, `hybrid@0.0+doctype_oracle`, `hybrid@0.2+doctype_oracle`, `hybrid@0.5+doctype_oracle`, `hybrid@0.0+doctype_mcp`, `hybrid@0.2+doctype_mcp`, `hybrid@0.5+doctype_mcp`
- Top-K: 10  |  Top-N pool: 50  |  k_rrf: 60
- Embedding model: `snowflake-arctic-embed-l-v2.0` (1024-d)

## 2. Overall metrics by config
```
                           hit@1  hit@3  hit@5  hit@10  adv_hit@5  adv_hit@10    mrr  ndcg@10
config                                                                                       
bm25_only                  0.496  0.728  0.784   0.824      0.904       0.944  0.618    0.669
hybrid@0.0+doctype_mcp     0.328  0.480  0.496   0.528      0.584       0.616  0.405    0.435
hybrid@0.0+doctype_oracle  0.528  0.760  0.816   0.872      0.944       0.984  0.653    0.707
hybrid@0.2                 0.504  0.720  0.776   0.832      0.928       0.960  0.624    0.675
hybrid@0.2+doctype_mcp     0.320  0.448  0.472   0.528      0.592       0.616  0.392    0.425
hybrid@0.2+doctype_oracle  0.536  0.768  0.816   0.880      0.960       0.992  0.660    0.714
hybrid@0.3                 0.520  0.712  0.768   0.808      0.928       0.952  0.626    0.671
hybrid@0.5                 0.520  0.680  0.712   0.816      0.904       0.952  0.608    0.658
hybrid@0.5+doctype_mcp     0.336  0.408  0.432   0.496      0.592       0.608  0.380    0.407
hybrid@0.5+doctype_oracle  0.544  0.720  0.760   0.864      0.952       0.984  0.645    0.697
hybrid@0.7                 0.496  0.640  0.680   0.768      0.864       0.920  0.578    0.623
vector_only                0.424  0.584  0.632   0.736      0.840       0.888  0.519    0.570
```

**Best config by MRR:** `hybrid@0.2+doctype_oracle`

## 3. Classifier (MCP simulation)
- Tool-call agreement (gold in predicted): **0.616**
- Coverage (non-empty predictions): **1.000**
- Avg doc_types returned / query: **1.38**

Agreement by gold doc_type:
```
                  mean  count
gold                         
ANALYSIS_REPORT  0.533     15
CSA              0.733     15
IR_LESSONS       0.550     20
JOINT_CSA        0.500     30
MAR              0.700     30
STOPRANSOMWARE   0.733     15
```

## 4. Per document_type (hit@5)
```
config           bm25_only  hybrid@0.0+doctype_mcp  hybrid@0.0+doctype_oracle  hybrid@0.2  hybrid@0.2+doctype_mcp  hybrid@0.2+doctype_oracle  hybrid@0.3  hybrid@0.5  hybrid@0.5+doctype_mcp  hybrid@0.5+doctype_oracle  hybrid@0.7  vector_only
document_type                                                                                                                                                                                                                                   
ANALYSIS_REPORT      0.867                   0.467                      0.867       0.733                   0.333                      0.867       0.667       0.600                   0.267                      0.733       0.600        0.600
CSA                  0.867                   0.667                      0.867       0.867                   0.667                      0.867       0.867       0.867                   0.667                      0.867       0.867        0.933
IR_LESSONS           0.800                   0.550                      0.950       0.800                   0.550                      0.950       0.800       0.750                   0.500                      0.900       0.650        0.600
JOINT_CSA            0.867                   0.400                      0.867       0.867                   0.367                      0.867       0.867       0.800                   0.367                      0.800       0.767        0.700
MAR                  0.667                   0.467                      0.667       0.667                   0.467                      0.667       0.667       0.567                   0.367                      0.600       0.500        0.400
STOPRANSOMWARE       0.667                   0.533                      0.733       0.733                   0.533                      0.733       0.733       0.733                   0.533                      0.733       0.800        0.733
```

## 5. Hybrid alpha sweep
```
       hit@5  hit@10    mrr  ndcg@10
alpha                               
0.0    0.784   0.824  0.618    0.669
0.2    0.776   0.832  0.624    0.675
0.3    0.768   0.808  0.626    0.671
0.4    0.744   0.816  0.629    0.674
0.5    0.712   0.816  0.608    0.658
0.6    0.688   0.776  0.581    0.628
0.7    0.680   0.768  0.578    0.623
0.8    0.680   0.760  0.571    0.616
1.0    0.632   0.736  0.519    0.570
```

**Best alpha by MRR:** `0.4`

## 6. Failures (hit@10 == 0, config=`hybrid@0.2+doctype_oracle`)
- 15 of 125 queries failed
  - [JOINT_CSA] What type of files are listed in the advisory related to Russian Military Cyber Actors targeting US and Global Critical Infrastructure?
  - [JOINT_CSA] Which countries' cybersecurity authorities collaborated to develop the advisory on protecting against cyber threats to managed service providers and their customers?
  - [JOINT_CSA] What are the MITRE ATT&CK tactics associated with the Iranian cyber actors involved in ransomware attacks as mentioned in the advisory?
  - [MAR] What malware family is the identified ELF 64-bit file associated with in the advisory MAR-10296782-2.v1?
  - [MAR] What type of malware is identified in the advisory, and what capabilities does it possess regarding file management and communication with its command and control server?
  - [MAR] What does CISA recommend regarding the management of antivirus signatures and operating system patches to strengthen an organization's security posture?
  - [MAR] What type of connections does the TAIDOOR Trojan establish with external domains as indicated in the advisory?
  - [MAR] What is the name of the malicious PE32 executable described in the advisory that is associated with North Korean Trojan HOPLIGHT?
  - [MAR] What best practices does CISA recommend for strengthening the security posture of systems using Pulse Connect Secure?
  - [MAR] What is the MD5 hash of the North Korean Trojan identified as HOPLIGHT in the advisory MAR-10135536-8?
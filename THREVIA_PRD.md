# Product Requirements Document (PRD)
## THREVIA — Threat Recognition, Evaluation & Visualization using Intelligent Analytics

**Version:** 1.0
**Date:** August 2026
**Status:** Draft

---

## 1. Overview

### 1.1 Purpose
THREVIA is a big data analytics platform for detecting, classifying, and visualizing cybersecurity threats from large-scale network traffic and security logs. It combines distributed storage and processing (Hadoop/Spark), machine learning-based classification, fast membership lookups (Bloom Filters), real-time anomaly detection, and graph-based network analysis into a single system with an interactive dashboard.

### 1.2 Problem Statement
Modern networks generate log and traffic data at a volume and velocity that traditional single-node security tools cannot process effectively. Analysts need a scalable system that can ingest massive datasets, detect known and emerging threats, identify relationships between malicious actors, and present findings in a way that supports fast decision-making.

### 1.3 Goals
- Process large-scale network traffic/log datasets using distributed computing
- Classify traffic as normal or malicious using machine learning
- Cluster similar threat behaviors for pattern discovery
- Provide fast, low-latency lookups against known malicious indicators
- Detect real-time spikes/anomalies in traffic
- Model network entities as a graph to surface malicious communities and highly connected nodes
- Present all of the above through an interactive, analyst-friendly dashboard

### 1.4 Non-Goals
- This system is not a replacement for a production SIEM/SOC platform
- Not intended to perform automated remediation/blocking (detection and visualization only, v1)
- Not designed for encrypted traffic decryption or deep packet payload inspection

---

## 2. Target Users

| User | Needs |
|---|---|
| Security Analyst | Fast visibility into threats, suspicious IPs, and attack trends |
| Data/ML Engineer | A pipeline to test and improve detection models |
| Project Evaluator / Stakeholder | Clear demonstration of big data + ML + visualization integration |

---

## 3. System Architecture

```
Raw Logs / Network Traffic
        │
        ▼
   [HDFS Storage] ──► [MapReduce Batch Jobs]
        │
        ▼
 [Apache Spark / PySpark]
   - Preprocessing
   - Feature Extraction
   - Statistical Analysis
        │
        ├──► [Spark MLlib] — Classification + Clustering
        │
        ├──► [Bloom Filter] — Known malicious IP/domain lookup
        │
        ├──► [Spark Structured Streaming] — Spike/anomaly detection
        │
        ▼
 [MongoDB / Cassandra] — Store processed security events
        │
        ├──► [Graph Layer (GraphFrames/NetworkX)] — Entity relationships, communities
        │
        ▼
 [Interactive Dashboard] — Trends, severity, IPs, network graph, model performance
```

---

## 4. Functional Requirements

### 4.1 Data Ingestion & Storage
- FR1: System shall ingest network traffic/log datasets (e.g., NetFlow, IDS logs, PCAP-derived CSV) into HDFS
- FR2: System shall support batch loading of standard public datasets (CICIDS2017, NSL-KDD, or UNSW-NB15)
- FR3: System shall run at least one MapReduce job for large-scale batch aggregation

### 4.2 Preprocessing & Feature Engineering
- FR4: System shall clean and normalize raw log data using PySpark
- FR5: System shall extract relevant features (flow duration, byte/packet counts, protocol, port, flags, connection rate, etc.)
- FR6: System shall handle missing/malformed data gracefully

### 4.3 Machine Learning
- FR7: System shall classify traffic as normal or malicious using Spark MLlib (e.g., Random Forest, Logistic Regression, or Gradient Boosted Trees)
- FR8: System shall support multi-class classification of attack types where labels are available (DoS, Probe, R2L, U2R, etc.)
- FR9: System shall cluster similar threat behaviors using an unsupervised algorithm (e.g., K-Means)
- FR10: System shall report model performance metrics: accuracy, precision, recall, F1-score, confusion matrix

### 4.4 Threat Intelligence Lookup
- FR11: System shall implement a Bloom Filter for fast membership checks of known malicious IPs/domains
- FR12: System shall support periodic updates to the Bloom Filter's underlying blocklist

### 4.5 Real-Time Detection
- FR13: System shall use stream processing to detect sudden spikes in suspicious activity
- FR14: System shall generate alerts/flags when anomaly thresholds are exceeded

### 4.6 Data Storage (Processed Events)
- FR15: System shall persist processed, classified security events in MongoDB or Cassandra
- FR16: Storage schema shall accommodate heterogeneous event types (different log formats/fields)

### 4.7 Graph Analysis
- FR17: System shall model network entities (IPs, domains, hosts) as nodes and interactions as edges
- FR18: System shall identify highly connected malicious nodes (centrality measures)
- FR19: System shall detect communities/clusters of related malicious activity (e.g., Louvain method)

### 4.8 Dashboard & Visualization
- FR20: Dashboard shall visualize attack trends over time
- FR21: Dashboard shall display threat severity levels
- FR22: Dashboard shall list/highlight suspicious IPs
- FR23: Dashboard shall render the network relationship graph interactively
- FR24: Dashboard shall display ML model performance metrics
- FR25: Dashboard shall support filtering (by time range, attack type, severity)

---

## 5. Non-Functional Requirements

| Category | Requirement |
|---|---|
| Scalability | Must handle datasets in the multi-GB range using distributed processing |
| Performance | Bloom Filter lookups must be near-constant time; streaming detection latency should be low (seconds, not minutes) |
| Reliability | Batch jobs should be re-runnable/idempotent |
| Usability | Dashboard should be understandable by a non-ML-expert analyst |
| Maintainability | Modular pipeline stages (ingestion, processing, ML, storage, viz) should be independently testable |
| Portability | System should run in a containerized environment (Docker) for reproducibility |

---

## 6. Technology Stack

| Layer | Technology |
|---|---|
| Distributed Storage | Hadoop HDFS |
| Batch Processing | Hadoop MapReduce, Apache Spark |
| Processing/ML Framework | PySpark, Spark MLlib |
| Fast Lookup | Bloom Filter (custom or pybloom-live) |
| Streaming | Spark Structured Streaming (optionally + Kafka) |
| Database | MongoDB or Cassandra |
| Graph Processing | GraphFrames / Spark GraphX / NetworkX |
| Dashboard | Streamlit or Dash (Plotly), optionally Grafana |
| Datasets | CICIDS2017, NSL-KDD, UNSW-NB15, CTU-13 |
| Deployment | Docker / Docker Compose |

---

## 7. Milestones / Build Phases

1. **Foundation** — Environment setup, HDFS storage, dataset ingestion
2. **Batch Processing** — PySpark cleaning, feature extraction, one MapReduce job
3. **Machine Learning** — Classification + clustering pipeline, evaluation metrics
4. **Real-Time Layer** — Bloom Filter + streaming spike detection
5. **Graph Analysis** — Entity graph construction, centrality, community detection
6. **Dashboard** — Visualization of trends, IPs, graph, model performance
7. **Integration & Polish** — End-to-end testing, documentation, tuning

---

## 8. Success Metrics

- Classification model achieves acceptable accuracy/F1 on a held-out test set (target benchmark to be set once dataset is chosen, e.g. >90% on NSL-KDD binary classification)
- Bloom Filter returns lookups with no false negatives and an acceptably low false positive rate
- Streaming component detects injected/simulated traffic spikes within a defined time window
- Dashboard loads and renders within a reasonable time for the target dataset size
- Graph analysis correctly surfaces known malicious clusters when tested against labeled attack scenarios

---

## 9. Risks & Open Questions

| Risk/Question | Notes |
|---|---|
| Dataset choice | Needs to be finalized early — affects feature engineering and model design |
| Single-node vs multi-node cluster | Determines realistic scale of "big data" claims |
| Real-time vs simulated streaming | True real-time ingestion may require Kafka; simulated replay may be sufficient for v1 |
| MongoDB vs Cassandra | MongoDB is faster to prototype with; Cassandra scales better for write-heavy time-series data — decision needed before Phase 1 |
| Bloom Filter blocklist source | Need a reliable, up-to-date source of known malicious IPs/domains |
| Graph library choice | GraphFrames integrates natively with Spark but has a steeper setup; NetworkX is simpler but not distributed |

---

## 10. Appendix

**Candidate Datasets:**
- NSL-KDD — classic, smaller, good for initial prototyping
- CICIDS2017 / CICIDS2018 — modern, realistic attack scenarios, larger scale
- UNSW-NB15 — good feature diversity
- CTU-13 — botnet-focused, useful for graph/community analysis

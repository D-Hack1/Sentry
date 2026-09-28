# 🔐 AI-Powered IPsec VPN Protocol Analyzer

An AI-powered security assessment framework for analyzing IPsec VPN
sessions, identifying VPN configurations, classifying encrypted traffic
from ESP metadata, detecting anomalous sessions, and generating security
assessment reports.

The system combines **strongSwan, Scapy, Zeek, Kafka, Elasticsearch,
FastAPI, XGBoost, Isolation Forest, SHAP, and a React dashboard** into
an end-to-end analysis pipeline.

> **SIH 2026 Project --- AI-Powered IPsec VPN Protocol Analyzer and
> Security Assessment Framework**

------------------------------------------------------------------------

## 🚀 What Does This Project Do?

IPsec encrypts the actual payload of network traffic, making traditional
payload-based traffic inspection difficult. This project analyzes the
information that remains observable around the encrypted traffic.

The system works in two major stages:

1.  **IPsec/IKE analysis**
    -   Dissects IKEv1/IKEv2 negotiation packets.
    -   Identifies the negotiated cryptographic configuration.
    -   Extracts parameters such as cipher suite, DH group, PFS,
        authentication algorithm, and tunnel mode.
2.  **Encrypted traffic analysis**
    -   Does **not decrypt ESP payloads**.
    -   Uses metadata such as packet sizes, inter-arrival times, burst
        patterns, throughput, and bidirectional traffic ratios.
    -   Uses ML models to classify the traffic type.
    -   Uses anomaly detection and explainability to identify suspicious
        sessions.

The result is a complete security assessment containing a **security
score, severity, risk flags, AI confidence, anomaly score, SHAP
evidence, and recommendations**.

------------------------------------------------------------------------

## ✨ Key Features

-   🔎 **IKEv1 / IKEv2 protocol dissection**
-   🔐 **IPsec cryptographic configuration identification**
-   📦 **ESP metadata-based encrypted traffic classification**
-   🧠 **XGBoost-based machine learning**
-   🚨 **Isolation Forest anomaly detection**
-   💡 **SHAP-based explainability**
-   🛡️ **Deterministic cryptographic security scoring**
-   📊 **Live session dashboard**
-   ⚡ **Kafka-based streaming pipeline**
-   🔍 **Elasticsearch session storage**
-   📡 **Server-Sent Events (SSE) live metrics**
-   📄 **Automated PDF security reports**
-   🧩 **Session correlation**
-   🐳 **Docker-based isolated IPsec lab**
-   📈 **Training and evaluation pipeline**

------------------------------------------------------------------------

# 🏗️ System Architecture

``` text
                     ┌─────────────────────────┐
                     │       IPsec Lab         │
                     │                         │
                     │  strongSwan Initiator   │
                     │          │              │
                     │       IPsec VPN          │
                     │          │              │
                     │  strongSwan Responder   │
                     └──────────┬──────────────┘
                                │
                                ▼
                     ┌─────────────────────────┐
                     │       PCAP Capture      │
                     │   tcpdump / tshark      │
                     └──────────┬──────────────┘
                                │
                                ▼
              ┌─────────────────────────────────────┐
              │          Feature Pipeline            │
              │                                     │
              │  IKE Parser ──────► IKE Features   │
              │       │                             │
              │  ESP Metadata ────► Traffic Feats  │
              └─────────────────┬───────────────────┘
                                │
                                ▼
                     ┌─────────────────────────┐
                     │         Kafka           │
                     │                         │
                     │ raw-features            │
                     │ inference-results       │
                     │ alerts                  │
                     │ pipeline-metrics        │
                     └──────────┬──────────────┘
                                │
                                ▼
                     ┌─────────────────────────┐
                     │       FastAPI           │
                     │                         │
                     │ Protocol Model          │
                     │ Traffic Model           │
                     │ Isolation Forest        │
                     │ Security Scorer         │
                     │ SHAP Explainability     │
                     └──────────┬──────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
          ┌──────────────────┐    ┌──────────────────┐
          │  Elasticsearch   │    │   PDF Reports    │
          │                  │    │                  │
          │ IPsec Sessions   │    │ Security Report  │
          │ Alerts           │    │ Recommendations  │
          └────────┬─────────┘    └──────────────────┘
                   │
                   ▼
          ┌──────────────────────┐
          │    React Dashboard   │
          │                      │
          │ Live Feed            │
          │ Session Details      │
          │ Statistics           │
          │ Live Metrics         │
          │ Security Reports     │
          └──────────────────────┘
```

------------------------------------------------------------------------

# 🎯 Classification Targets

## VPN / Protocol Configuration

  Feature       Values
  ------------- --------------------------------------------------------
  IKE Version   `ikev1`, `ikev2`
  Mode          `tunnel`, `transport`
  Cipher        `aes128_cbc`, `aes256_cbc`, `aes128_gcm`, `aes256_gcm`
  DH Group      `group2`, `group5`, `group14`, `group19`, `group20`
  PFS           `enabled`, `disabled`

## Encrypted Traffic Classification

The ESP payload remains encrypted. Classification is performed using
metadata.

  Traffic Class
  -----------------
  `web`
  `voip`
  `video`
  `file_transfer`
  `icmp`

------------------------------------------------------------------------

# 🧠 Machine Learning Pipeline

The project uses multiple models, each solving a different problem.

## 1. Protocol / Configuration Identification

**Input:** IKE-derived features

The protocol model identifies VPN configuration parameters such as:

-   Cipher suite
-   DH group
-   Mode
-   PFS status

The specification uses XGBoost for this task.

------------------------------------------------------------------------

## 2. Encrypted Traffic Classification

**Input:** ESP metadata features

The traffic model predicts:

``` text
web
voip
video
file_transfer
icmp
```

Important features include:

-   Mean packet size
-   Packet-size standard deviation
-   Minimum / maximum packet size
-   Mean inter-arrival time
-   Inter-arrival-time standard deviation
-   Burst count
-   Burst size
-   Bytes per second
-   Packets per second
-   Bidirectional traffic ratio

Because ESP payloads are encrypted, the classifier relies only on
observable traffic metadata.

------------------------------------------------------------------------

## 3. Anomaly Detection

An **Isolation Forest** is trained using benign/well-configured ESP
sessions.

It produces an anomaly score that helps identify traffic patterns that
differ from normal sessions.

------------------------------------------------------------------------

## 4. Explainability

SHAP is used to explain model predictions.

The system extracts important features and converts them into
human-readable explanations such as:

``` text
High burst count — consistent with file transfer or streaming
Variable inter-arrival times — consistent with bursty web traffic
High throughput — consistent with video or file transfer
Perfect Forward Secrecy status
DH group used in key exchange
```

------------------------------------------------------------------------

# 🛡️ Security Scoring

Security scoring is intentionally **rule-based rather than ML-based**.

The scorer starts at:

``` text
100
```

Security rules apply penalties and bonuses based on the VPN
configuration.

Examples include:

  Configuration       Effect
  ------------------- -----------------------
  DH Group 2          Large penalty
  DH Group 5          Penalty
  AES-128-CBC         Penalty
  PFS disabled        Penalty
  Long key lifetime   Penalty
  IKEv1               Penalty
  NAT-T               Informational penalty
  AES-256-GCM         Bonus
  DH Group 19         Bonus
  DH Group 20         Bonus

The final score is clamped to:

``` text
0–100
```

Severity is derived from the score:

``` text
critical  < 40
high      < 60
medium    < 75
low       < 90
info      >= 90
```

------------------------------------------------------------------------

# 📡 Data Flow

A typical session moves through the following pipeline:

``` text
IPsec Traffic
     │
     ▼
PCAP Capture
     │
     ▼
IKE Parser ───────────────┐
     │                   │
     ▼                   │
IKE Features              │
                         ▼
ESP Packet Analysis ──► Feature Pipeline
                         │
                         ▼
                  IPsecFeatureRow
                         │
                         ▼
                      Kafka
                         │
                         ▼
                     FastAPI
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
  Protocol Model   Traffic Model   Isolation Forest
        │                │                │
        └────────────────┼────────────────┘
                         ▼
                  Security Scorer
                         │
                         ▼
                   SHAP Explainability
                         │
                         ▼
                  Security Assessment
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
       Elasticsearch            PDF Report
              │
              ▼
       React Dashboard
```

------------------------------------------------------------------------

# 📦 Core Feature Schema

The central data structure is `IPsecFeatureRow`.

It contains four major groups of information:

### Session Identity

``` text
session_id
timestamp
initiator_ip
responder_ip
initiator_port
responder_port
duration
```

### IKE Features

``` text
ike_version
ike_exchange_type
ike_initiator_spi
sa_proposal_count
ke_dh_group
ike_nat_traversal
ike_packet_count
ike_handshake_duration
```

### Inferred VPN Configuration

``` text
mode
cipher_suite
auth_algo
dh_group
pfs_enabled
key_lifetime_sec
esp_spi
```

### ESP Metadata

``` text
esp_packet_count
esp_bytes_total
esp_pkt_size_mean
esp_pkt_size_std
esp_pkt_size_min
esp_pkt_size_max
esp_iat_mean
esp_iat_std
esp_iat_min
esp_iat_max
esp_burst_count
esp_burst_size_mean
esp_bytes_per_sec
esp_pkts_per_sec
bidir_ratio
```

The predicted fields are:

``` text
traffic_class
traffic_confidence
```

------------------------------------------------------------------------

# 🔌 Backend API

The FastAPI backend exposes the following main endpoints.

  Endpoint               Purpose
  ---------------------- -----------------------------------------
  `POST /analyze`        Analyze an IPsec feature row
  `GET /sessions`        Query analyzed sessions
  `GET /sessions/{id}`   Retrieve a specific session
  `GET /report/{id}`     Generate/download a PDF security report
  `GET /stats`           Session and security statistics
  `GET /metrics`         Live pipeline metrics using SSE
  `GET /health`          Backend/service health status

### `POST /analyze`

The analysis pipeline performs:

``` text
1. Protocol identification
2. Traffic classification
3. Anomaly detection
4. Security scoring
5. SHAP explanation
6. Elasticsearch persistence
7. Final response generation
```

A response contains information such as:

``` json
{
  "session_id": "...",
  "ike_version": 2,
  "mode": "tunnel",
  "cipher_suite": "aes256_gcm",
  "dh_group": "group19",
  "pfs_enabled": true,
  "traffic_class": "web",
  "traffic_confidence": 0.91,
  "security_score": 92,
  "severity": "info",
  "anomaly_score": 0.12,
  "risk_flags": [],
  "evidence": [],
  "ai_confidence": 0.94
}
```

------------------------------------------------------------------------

# 📊 Dashboard

The React dashboard contains five primary views.

## Live Feed

Displays recently analyzed VPN sessions with:

-   Timestamp
-   Initiator → responder
-   IPsec mode
-   Cipher suite
-   DH group
-   PFS status
-   Security score
-   Severity

------------------------------------------------------------------------

## Session Details

Provides a detailed analysis of an individual session:

-   IKE negotiation summary
-   VPN configuration
-   Security score
-   Severity
-   Risk flags
-   SHAP evidence
-   Traffic class
-   Traffic confidence
-   Anomaly score
-   AI confidence

------------------------------------------------------------------------

## Statistics

Visualizes:

-   Cipher-suite distribution
-   DH-group distribution
-   PFS enabled vs disabled
-   Security-score distribution
-   Weak configurations

------------------------------------------------------------------------

## Live Metrics

The dashboard consumes the `/metrics` SSE endpoint.

Live metrics include:

``` text
Sessions/sec
MB/sec
Kafka queue depth
Pipeline latency
```

------------------------------------------------------------------------

## Security Report

Provides an HTML/PDF security assessment containing:

-   Executive summary
-   Session metadata
-   Security score
-   Risk flags
-   Threat matrix
-   AI confidence
-   Recommendations

------------------------------------------------------------------------

# 🐳 Infrastructure

The project uses Docker to create an isolated IPsec lab.

### Core Containers

``` text
initiator
responder
monitor
```

The lab uses:

-   strongSwan
-   tcpdump
-   tshark
-   iperf3
-   curl
-   wget
-   ffmpeg

Additional infrastructure:

``` text
Kafka
Zookeeper
Elasticsearch
```

------------------------------------------------------------------------

# 🔄 Kafka Topics

Four Kafka topics are used:

  Topic                 Purpose
  --------------------- ----------------------------------------
  `raw-features`        Feature rows generated by the pipeline
  `inference-results`   Model inference results
  `alerts`              High-risk sessions
  `pipeline-metrics`    Throughput and latency metrics

The intended pipeline is:

``` text
PCAP
 ↓
Feature Extraction
 ↓
raw-features
 ↓
FastAPI /analyze
 ↓
inference-results
 ↓
alerts (when security_score < 50)
```

------------------------------------------------------------------------

# 🔍 Elasticsearch

Analyzed sessions are stored in Elasticsearch.

The session index contains fields including:

``` text
session_id
timestamp
initiator_ip
responder_ip
ike_version
mode
cipher_suite
dh_group
pfs_enabled
key_lifetime_sec
traffic_class
traffic_confidence
security_score
severity
anomaly_score
risk_flags
ai_confidence
report_id
```

This allows the dashboard and API to query historical sessions
efficiently.

------------------------------------------------------------------------

# 📁 Project Structure

``` text
.
├── docker-compose.yml
├── .env
├── .env.example
├── Makefile
├── LAB.md
├── INTEGRATION.md
├── API_CONTRACT.md
│
├── initiator/
│   └── Dockerfile
│
├── responder/
│   └── Dockerfile
│
├── monitor/
│   └── Dockerfile
│
├── capture/
│   ├── run_matrix.sh
│   ├── gen_config.py
│   └── verify_sa.sh
│
├── traffic/
│   ├── web_traffic.py
│   ├── voip_sim.py
│   ├── video_stream.py
│   ├── file_transfer.py
│   └── icmp_flood.py
│
├── data/
│   ├── raw/
│   ├── labels/
│   ├── features/
│   └── verify.py
│
├── zeek/
│   └── scripts/
│       ├── ike.zeek
│       └── esp.zeek
│
├── features/
│   ├── schema.py
│   ├── security_rules.py
│   ├── ike_field_table.py
│   ├── pipeline.py
│   ├── encode.py
│   ├── ike_parser.py
│   └── watcher.py
│
├── kafka/
│   ├── producer.py
│   ├── consumer.py
│   ├── metrics_producer.py
│   └── health_check.py
│
├── es/
│   ├── init_index.py
│   └── health_check.py
│
├── ml/
│   ├── train.py
│   ├── evaluate.py
│   ├── inference.py
│   ├── explainability.py
│   ├── scorer.py
│   ├── protocol_model.joblib
│   ├── traffic_model.joblib
│   ├── encoder.joblib
│   └── tests/
│
├── api/
│   ├── main.py
│   ├── correlator.py
│   └── report_generator.py
│
├── reports/
│   └── template.html
│
└── dashboard/
    └── src/
        ├── api/
        └── views/
```

------------------------------------------------------------------------

# ⚙️ Technology Stack

  Layer               Technology
  ------------------- -------------------------
  VPN                 strongSwan / IPsec
  Packet Capture      tcpdump / tshark
  Packet Parsing      Scapy
  Network Analysis    Zeek
  Messaging           Apache Kafka
  Coordination        Zookeeper
  Backend             FastAPI
  Database / Search   Elasticsearch
  ML                  XGBoost
  Anomaly Detection   Isolation Forest
  Explainability      SHAP
  Optimization        Optuna
  PDF Generation      WeasyPrint
  Frontend            React + Vite
  Charts              Recharts
  Styling             Tailwind CSS
  Infrastructure      Docker / Docker Compose

------------------------------------------------------------------------

# 🧪 Dataset Generation

The project generates its own controlled dataset using a configuration
matrix.

The capture matrix varies:

``` text
Modes:
  tunnel
  transport

Ciphers:
  aes128-cbc
  aes256-cbc
  aes128-gcm
  aes256-gcm

DH:
  modp1024
  modp2048
  modp4096
  ecp256
  ecp384

PFS:
  yes
  no
```

Traffic types:

``` text
web
voip
video
file_transfer
icmp
```

Each configuration is captured into a PCAP and paired with a
ground-truth label.

The intended dataset contains approximately **100 sessions**, with
coverage across the VPN configuration and traffic combinations.

------------------------------------------------------------------------

# 🏋️ Training

The training pipeline is launched through:

``` bash
python ml/train.py
```

The training process produces:

``` text
protocol_model.joblib
traffic_model.joblib
encoder.joblib
optuna_study_traffic.pkl
```

Evaluation can be performed with:

``` bash
python ml/evaluate.py
```

Expected evaluation artifacts include:

``` text
protocol_classification_report.txt
traffic_classification_report.txt
protocol_confusion_matrix.png
traffic_confusion_matrix.png
```

------------------------------------------------------------------------

# 🔧 Configuration

Create a local environment file:

``` bash
cp .env.example .env
```

Important configuration variables include:

``` env
KAFKA_BOOTSTRAP=localhost:9092
ES_HOST=localhost
ES_PORT=9200
STRONGSWAN_CTL=...
```

Do not commit secrets or machine-specific credentials.

------------------------------------------------------------------------

# ▶️ Running the Project

## 1. Start the infrastructure

``` bash
docker compose up -d
```

Check the running containers:

``` bash
docker compose ps
```

------------------------------------------------------------------------

## 2. Verify Kafka

``` bash
python kafka/health_check.py
```

The expected Kafka topics are:

``` text
raw-features
inference-results
alerts
pipeline-metrics
```

------------------------------------------------------------------------

## 3. Verify Elasticsearch

``` bash
python es/health_check.py
```

The Elasticsearch service should be reachable on:

``` text
http://localhost:9200
```

------------------------------------------------------------------------

## 4. Start the FastAPI backend

From the API directory:

``` bash
uvicorn main:app --reload --port 8000
```

The API will be available at:

``` text
http://localhost:8000
```

FastAPI documentation:

``` text
http://localhost:8000/docs
```

------------------------------------------------------------------------

## 5. Start the dashboard

``` bash
cd dashboard
npm install
npm run dev
```

The Vite development server normally runs on:

``` text
http://localhost:5173
```

------------------------------------------------------------------------

# 🩺 Health Check

Use:

``` bash
curl http://localhost:8000/health
```

The health endpoint reports the status of:

-   FastAPI
-   ML models
-   Isolation Forest
-   Kafka
-   Elasticsearch
-   Application uptime

------------------------------------------------------------------------

# 🧩 Development Workflow

A complete session follows this sequence:

``` text
1. Configure strongSwan
        ↓
2. Establish IPsec tunnel
        ↓
3. Generate traffic
        ↓
4. Capture packets
        ↓
5. Parse IKE packets
        ↓
6. Extract ESP metadata
        ↓
7. Build IPsecFeatureRow
        ↓
8. Publish to Kafka
        ↓
9. Run ML inference
        ↓
10. Calculate security score
        ↓
11. Generate SHAP evidence
        ↓
12. Store in Elasticsearch
        ↓
13. Stream metrics / alerts
        ↓
14. Display in dashboard
        ↓
15. Generate security report
```

------------------------------------------------------------------------

# 👥 Team Responsibilities

The project is divided into the following workstreams:

  -----------------------------------------------------------------------
  Team Member                         Responsibility
  ----------------------------------- -----------------------------------
  **Ebin**                            Backend, shared schema, Kafka
                                      integration, FastAPI, reports

  **Nived**                           Docker IPsec lab, capture
                                      automation, Kafka/Elasticsearch
                                      infrastructure

  **Aadi**                            Traffic generation, IKE parser,
                                      Zeek, anomaly detection/inference

  **Gowri**                           ESP feature pipeline, SHAP
                                      explainability, security scorer

  **Sanjay**                          Dataset labels, model training,
                                      evaluation

  **Jaith**                           React dashboard and frontend
                                      integration
  -----------------------------------------------------------------------

The shared `features/schema.py` acts as the common contract between the
feature extraction, ML, backend, and frontend components.

------------------------------------------------------------------------

# 🔐 Security Design Principles

This project follows several important principles:

### No ESP payload decryption

Traffic classification uses metadata rather than attempting to decrypt
the contents of IPsec ESP packets.

### Controlled lab environment

The IPsec infrastructure is intended to run inside an isolated Docker
network.

### Explainable ML

Predictions are accompanied by SHAP-based evidence where supported.

### Deterministic security scoring

The cryptographic security score is calculated using explicit rules
rather than relying solely on an opaque ML prediction.

### Separation of concerns

``` text
Network Capture
      ↓
Feature Extraction
      ↓
Messaging
      ↓
ML Inference
      ↓
Security Assessment
      ↓
Storage
      ↓
Visualization
```

------------------------------------------------------------------------

# 📈 Intended Output

For each analyzed VPN session, the system produces:

``` text
VPN configuration
        +
Traffic classification
        +
Traffic confidence
        +
Anomaly score
        +
Security score
        +
Severity
        +
Risk flags
        +
SHAP evidence
        +
Recommendations
```

This allows a user to understand not only **what configuration and
traffic pattern were detected**, but also **why the system reached its
conclusion and what security issues were identified**.

------------------------------------------------------------------------

# 🗺️ Project Roadmap

### Phase 1 --- Infrastructure

-   [x] Docker IPsec lab
-   [x] Kafka infrastructure
-   [x] Elasticsearch
-   [ ] Automated capture matrix

### Phase 2 --- Feature Extraction

-   [ ] IKE parser
-   [ ] Zeek IKE analyzer
-   [ ] ESP metadata pipeline
-   [ ] Feature encoding

### Phase 3 --- Machine Learning

-   [ ] Protocol identification model
-   [ ] Traffic classification model
-   [ ] Isolation Forest
-   [ ] Model evaluation
-   [ ] SHAP explainability

### Phase 4 --- Backend

-   [ ] FastAPI analysis endpoint
-   [ ] Session APIs
-   [ ] Statistics API
-   [ ] SSE metrics
-   [ ] PDF report generation
-   [ ] Session correlation

### Phase 5 --- Dashboard

-   [ ] Live session feed
-   [ ] Session details
-   [ ] Statistics
-   [ ] Live metrics
-   [ ] Security reports
-   [ ] Responsive UI

### Phase 6 --- Integration

-   [ ] End-to-end pipeline test
-   [ ] PCAP replay
-   [ ] Model validation
-   [ ] Dashboard integration
-   [ ] Demo rehearsal

------------------------------------------------------------------------

# ⚠️ Disclaimer

This project is designed for **educational, research, and controlled
security-analysis environments**.

Only analyze network traffic and systems that you own or are explicitly
authorized to inspect.

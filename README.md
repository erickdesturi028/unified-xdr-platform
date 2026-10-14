# 🛡️ Unified XDR & EDR Platform

A high-performance Security Operations Center (SOC) telemetry collection, real-time threat detection, and active automated response platform built with **Go**, **Elasticsearch**, **Neo4j**, **gRPC**, and a **custom HTML5/JS Dashboard**.

---

## 🚀 Key Features

* **Real-time Telemetry Collection**: High-throughput ingestion engine written in Go[cite: 2].
* **Rule-based Detection Engine**: Driven by custom YAML rules (`rules.yaml`) for process execution, network activity, and suspicious behavior[cite: 2].
* **Dual Database Architecture**:
  * **Elasticsearch**: Fast log storage, search, and threat hunting queries[cite: 2].
  * **Neo4j**: Graph database for mapping attack paths and relationship topologies[cite: 2].
* **Unified SOC Dashboard**: Real-time event visualizer and threat hunting console served via Python[cite: 2].
* **Automated Containment (SOAR)**: gRPC-based host isolation and remediation controls[cite: 2].

---

## 🏗️ Project Architecture

unified-xdr-platform/
├── cmd/
│   ├── collector/        # Ingestion server & API entry point
│   └── simulator/        # Event simulation for testing detection rules
├── collector/
│   ├── api/              # REST API endpoints for alerts & logs
│   ├── engine/           # Real-time correlation & rule engine
│   ├── graph/            # Neo4j graph database integration
│   ├── parser/           # Telemetry log parsing logic
│   └── proto/            # gRPC protocol buffer definitions
├── dashboard/
│   └── index.html        # Unified SOC Web Console
├── docker-compose.yml    # Infrastructure setup (Elasticsearch & Neo4j)
├── go.mod                # Go module dependencies
├── rules.yaml            # Threat detection rules definition
└── README.md             # Project documentation

---

## ⚙️ Prerequisites

* **Go** (v1.20+)
* **Docker** & **Docker Compose**
* **Python** (v3.x)

---

## 🛠️ Quick Start Guide

### 1. Launch Infrastructure
Start the Elasticsearch and Neo4j database containers:
```bash
docker-compose up -d

2. Run the XDR Ingestion Engine
Start the central backend collector (handles REST API on :8080 and gRPC on :50051):
go run cmd/collector/main.go

3. Serve the SOC DashboardIn a separate terminal, open the dashboard directory and serve the interface on port 3000:Bashcd dashboard
python3 -m http.server 3000
Open your browser at http://localhost:3000 to access the SOC Analyst Console.4. Run Telemetry Simulator (Optional)To test rule triggers and see live security alerts on the dashboard:Bashgo run cmd/simulator/main.go
🔍 Threat Hunting & API EndpointsEndpointMethodPurpose/api/v1/alertsGETRetrieve real-time security alerts/api/v1/logsGETStream raw ingested telemetry/api/v1/containmentPOSTTrigger automated endpoint isolation📜 LicenseThis project is developed for educational and security research purposes.
---

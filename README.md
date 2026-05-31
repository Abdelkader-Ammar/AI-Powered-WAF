# AI-Powered WAF: A Two-Tier Cascade Architecture

![Golang](https://img.shields.io/badge/Golang-1.21+-00ADD8.svg)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C.svg)
![HuggingFace](https://img.shields.io/badge/HuggingFace-Transformers-F9AB00.svg)
![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen.svg)

> **Personal professional project — Academic Year 2025/2026**
> *National Institute of Applied Sciences and Technology (INSAT)*

---

## Project Overview

Traditional Web Application Firewalls (WAFs) rely on rigid, rule-based systems (regex) that struggle to detect modern, obfuscated cyber attacks. The core challenge in WAF engineering is the **latency vs. accuracy dilemma**: deep AI models are highly accurate but too slow for inline web traffic, while fast models miss complex attacks.

This project addresses the dilemma with a **two-tier ML cascade** fused with a **dynamic trust engine** and backed by a **runtime self-protection layer (RASP)**, giving strong detection while keeping the inline path sub-millisecond.

---

## Architecture

The pipeline runs sequentially and asynchronously to balance latency and deep analysis:

* **Dynamic Trust Engine (UEBA)**
  * A fast **Go** behavioral engine tracking user and entity behavior.
  * **Dual-layer scoring**: instantaneous risk for IPs (DDoS, scraping, recon, brute-force modules) and long-term reputation for authenticated users (via EWMA).
  * **Redis-backed**: syncs a minimal state map (`id -> trust score`) that dynamically adjusts WAF enforcement thresholds.
* **Orchestrator (WAF Proxy)**
  * A high-performance Go reverse proxy that intercepts all traffic. It consults the trust engine and routes requests through the filtering tiers.
* **Tier 0 — Inline Filter (LightGBM + Coraza)**
  * Sub-millisecond processing inside the orchestrator. Evaluates every request with fast TF-IDF features, alongside the Coraza (OWASP CRS) signature engine. Blocks obvious attacks and immediately allows benign traffic.
  * Requests in a "gray area" (uncertain prediction) pass to the backend but are copied to Tier 1 for deeper analysis.
* **Tier 1 — Deep NLP (RoBERTa)**
  * Asynchronous deep semantic analysis of the gray-area traffic forwarded by Tier 0. A confirmed attack lowers the originating entity's trust score and logs the payload for fine-tuning.
* **Tier 2 — RASP (Runtime Application Self-Protection)**
  * A C agent that observes what the backend actually *does* — process execution, file access, outbound connections, and database queries — via `LD_PRELOAD` interposition. It judges requests by runtime effect rather than payload, so it catches exploits that look benign to every payload-based tier. A confirmed exploit is ground truth and overrides the score to an immediate ban.
* **Admin Dashboard**
  * A real-time FastAPI + HTMX + SVG interface (no authored JavaScript) to monitor active attacks, review trust scores, and configure WAF thresholds. Runs on port `8082`.

---

## Quick Start

The fastest way to see the whole system end to end is the standalone demo, which stands up the full WAF in front of a deliberately-vulnerable target:

```sh
cd demo
cp .env.example .env
make up           # build and start every service (proxy :8080, admin API :8081, dashboard :8082)
make storyline    # run the scripted attack narrative (separate terminal)
make watch        # live request-journey console (separate terminal)
```

Open the dashboard at `http://localhost:8082` to watch decisions and confirmed exploitation in real time. See **[demo/README.md](demo/README.md)** for prerequisites, scenarios, and a full explanation of each tier and decision band. For development of an individual component, see its module README.

---

## The Team

| Name | Role / Sub-System | Description |
| :--- | :--- | :--- |
| **AMMAR Abdelkader** | **Tier 1 Deep NLP Analysis** | Engineering the RoBERTa model, streaming the dataset, and handling async inference. |
| **GRABA Mohamed Hadi** | **Tier 0 Inline ML** | Developing the sub-millisecond LightGBM/ONNX filter and extracting fast TF-IDF vectors. |
| **CHAFAI Salah** | **Admin Dashboard & RASP Engine** | Building the FastAPI + HTMX admin interface for monitoring and configuration, and engineering the Tier 2 RASP (Runtime Application Self-Protection) engine. |
| **KEFI Adem** | **Trust Engine (UEBA)** | Developing the Go TrustScore engine, dual-layer IP/user scoring, and Redis sync. |
| **KHEDIRI Oussema** | **Orchestrator** | Developing the high-performance Go WAF proxy that connects all ML tiers and the trust engine. |

---

## Repository Structure

```text
AI-Powered-WAF/
├── tier-0/             Go orchestrator (WAF proxy) + inline LightGBM/Coraza filter
├── trustscore/         Go UEBA engine (IP & user scoring, EWMA, RASP fusion, Redis sync)
├── tier1_roberta/      RoBERTa inference service (Tier 1 deep NLP)
├── tier1_deep_nlp/     RoBERTa training and evaluation scripts
├── rasp/               Tier 2 RASP engine (C, LD_PRELOAD syscall/DB interposition)
├── dashboard_py/       Admin dashboard (FastAPI + HTMX + SVG)
├── data_pipeline/      Dataset extraction and feedback-harvesting scripts
├── demo/               Standalone demo and testing harness (black-box)
├── .gitignore
└── README.md
```

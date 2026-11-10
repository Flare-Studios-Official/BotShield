# BotShield Behavioral Bot Detection Engine

## Overview

The BotShield Behavioral Bot Detection Engine identifies automated scrapers, vulnerability scanners, and anomalous traffic patterns by analyzing request sequences across sliding time windows.

The engine strictly rejects single-attribute classification (such as relying exclusively on the HTTP `User-Agent` string). Modern automated agents easily impersonate Chrome or Safari User-Agents, while legitimate programmatic tools may legitimately access public APIs.

---

## 1. Sliding Window Formulation

Evaluations compute metrics across two primary sliding intervals:
* **Cumulative Window ($W_{total}$)**: Default 300 seconds (5 minutes). Used for frequency, distinct endpoint counts, and status code distributions.
* **Burst Velocity Window ($W_{burst}$)**: Fixed 10 seconds. Sliding two-pointer algorithm computing the maximum cluster of requests executed in any contiguous 10-second slice.

---

## 2. Measurable Behavioral Signals

### Signal A: High Request Frequency
* **Identifier**: `HIGH_FREQUENCY`
* **Default Weight**: 25 points
* **Default Threshold**: 50 requests / 300s
* **Rationale**: Organic human users browsing content rarely maintain sustained velocities exceeding 10 requests per minute without pauses.

### Signal B: Short-Window Burst Velocity
* **Identifier**: `BURST_VELOCITY`
* **Default Weight**: 20 points
* **Default Threshold**: 15 requests / 10s
* **Rationale**: Flash spikes where a client fires 15+ calls in sub-10 second intervals indicate parallelized or asynchronous worker loops.

### Signal C: Path & Endpoint Enumeration
* **Identifier**: `ENDPOINT_PROBING`
* **Default Weight**: 20 points
* **Default Threshold**: 10 distinct paths or 2+ sensitive probe matches (`/.env`, `/wp-admin`, `/actuator/env`)
* **Rationale**: Content fuzzers systematically crawl wide swaths of unrelated endpoints looking for unindexed or administrative assets.

### Signal D: Repeated 404 Error Cascades
* **Identifier**: `EXCESSIVE_404S`
* **Default Weight**: 15 points
* **Default Threshold**: 5 HTTP 404 responses
* **Rationale**: Normal browsing produces occasional broken links, but high volumes of 404 errors strongly correlate with dictionary attacks and automated discovery.

### Signal E: Automation User-Agent Markers
* **Identifier**: `AUTOMATION_USER_AGENT`
* **Default Weight**: 10 points
* **Default Threshold**: Pattern match or absent header
* **Rationale**: Matches signatures such as `python-requests`, `curl`, `Go-http-client`, `Puppeteer`, or `Scrapy`. Weighted deliberately low (10 pts) so it acts as corroborating context rather than an automatic block trigger.

### Signal F: Rate Limit Violations
* **Identifier**: `RATE_LIMIT_VIOLATIONS`
* **Default Weight**: 20 points
* **Default Threshold**: 3 HTTP 429 status codes
* **Rationale**: Well-behaved clients back off exponentially upon receiving HTTP 429. Continued aggressive sending signifies an intentional denial-of-service or disregard for server limits.

### Signal G: Unnatural Inter-Request Timing
* **Identifier**: `RAPID_SEQUENCE`
* **Default Weight**: 10 points
* **Default Threshold**: Average interval &lt; 150ms
* **Rationale**: Programmatic scripts exhibit near-deterministic, machine-paced intervals (&lt;100ms) without human reading latency.

---

## 3. Scoring Matrix & Risk Tiers

The final heuristic risk indicator is calculated as:

$$\text{Score} = \min\left(100, \sum_{i \in \text{Triggered Rules}} \text{Weight}_i\right)$$

| Score Range | Risk Classification | Recommended Action |
|:---|:---|:---|
| **0 – 24** | **Low** | Allow standard traffic. |
| **25 – 49** | **Moderate** | Monitor; log telemetry for anomaly tracking. |
| **50 – 74** | **High** | Apply defensive rate-limiting or challenge mechanisms. |
| **75 – 100** | **Critical** | Block source IP or require cryptographic verification. |

---

## 4. Analyst False-Positive Management

To prevent blocking legitimate API consumers or automated partner integrations:
* Security analysts can review any detection record via `/api/bots/detections/{id}/review`.
* Reviews capture the analyst's identity, timestamp, and justification notes.
* Marking an IP as a **False Positive** preserves the telemetry evidence for auditability while exempting the client from operational blocks.

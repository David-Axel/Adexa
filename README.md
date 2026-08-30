# ADEXA

> [!WARNING]
> **AUTHORIZED SECURITY TESTING ONLY**
>
> ADEXA is intended exclusively for cybersecurity research, education, controlled laboratory environments, and security testing performed with explicit authorization.
>
> **Do not use ADEXA against systems, applications, networks, or infrastructure without explicit permission from the owner.**

## Adaptive Exploit Repair and Verification Framework

**ADEXA** is an AI-assisted cybersecurity research framework that analyzes failed security-testing payloads, generates repaired candidates, and verifies whether the repaired payload succeeds against an authorized test environment.

Instead of stopping when a security-testing payload fails, ADEXA follows an adaptive loop:

**Execute → Observe → Analyze → Repair → Verify → Learn**

> **Status:** Research prototype — active development

---

## The Problem

Automated security-testing tools can detect and test vulnerabilities using predefined payloads. However, when a security-testing attempt fails because of malformed syntax, incorrect assumptions, execution context, or other issues, adapting the payload can require manual intervention from a security tester.

ADEXA explores whether part of this iterative process can be automated.

The objective is not simply to generate more payloads. ADEXA aims to create a system capable of:

1. executing a security-testing payload,
2. observing the target response,
3. analyzing why the attempt failed,
4. selecting an appropriate repair strategy,
5. generating a repaired candidate,
6. executing the new candidate,
7. verifying whether it actually succeeds,
8. and retaining useful results for future decisions.

---

## Architecture

ADEXA is built around an adaptive execution loop connecting execution backends, analysis and AI components, verification logic, repair memory, and structured logging.

<p align="center">
  <img src="docs/images/adexa-architecture.png"
       alt="ADEXA adaptive exploit repair and verification architecture"
       width="900">
</p>

<p align="center">
  <em>ADEXA adaptive exploit repair and verification architecture.</em>
</p>

The architecture consists of several main components:

- **Core Adaptive Loop** — coordinates execution, observation, analysis, repair, and verification.
- **Execution Backends** — interact with controlled web and experimental binary targets.
- **AI Engine** — assists with failure analysis, repair decisions, candidate generation, and scoring.
- **Verification Engine** — determines whether a repaired candidate actually succeeds.
- **Repair Memory** — retains useful previous repairs that can support later decisions.
- **Run Storage & Logging** — records iterations, decisions, observations, and artifacts for analysis.

---

## Demo

ADEXA receives a security-testing payload, executes it against an authorized test environment, analyzes the unsuccessful attempt, generates a repaired candidate, and verifies the result.

<p align="center">
  <img src="docs/images/adexa-demo-terminal.png"
       alt="ADEXA SQL injection repair demonstration"
       width="900">
</p>

<p align="center">
  <em>ADEXA repairing and verifying a SQL injection payload against the local DVWA laboratory.</em>
</p>

The demonstration follows:

**Test → Analyze → Repair → Verify**

For example, ADEXA can start with a broken payload:

```text
'
````

and produce a repaired candidate:

```text
1' OR '1'='1
```

The repaired payload is then tested and verified against the controlled DVWA environment.

Run the demonstration with:

```bash
python3 adexa.py demo
```

---

## How ADEXA Works

```text
                 ┌───────────────┐
                 │ Input Payload │
                 └───────┬───────┘
                         │
                         ▼
                    ┌─────────┐
                    │ Execute │
                    └────┬────┘
                         │
                         ▼
                    ┌─────────┐
                    │ Observe │
                    └────┬────┘
                         │
                         ▼
                    ┌─────────┐
                    │ Analyze │
                    └────┬────┘
                         │
                         ▼
                    ┌────────┐
                    │ Repair │
                    └────┬───┘
                         │
                         ▼
                    ┌────────┐
                    │ Verify │
                    └───┬────┘
                        │
                 ┌──────┴──────┐
                 │             │
              SUCCESS        FAILURE
                 │             │
                 ▼             │
           Store Result        │
                               │
                         Repeat Loop
```

This allows ADEXA to treat security testing as an **adaptive process rather than a single exploit attempt**.

---

## Current Focus: SQL Injection

ADEXA's current web implementation focuses primarily on **SQL injection repair and verification** in controlled environments such as DVWA.

The current pipeline can work with malformed or unsuccessful SQL injection payloads and attempt to produce valid candidates while preserving the intended vulnerability-testing behavior.

Current capabilities include:

* malformed payload analysis,
* syntax and quotation repair,
* Boolean-based SQLi adaptation,
* time-based SQLi adaptation,
* candidate generation,
* candidate scoring,
* automated execution,
* exploit verification,
* previous-repair reuse,
* and structured iteration logging.

SQL injection represents **ADEXA's first specialist capability**, rather than the intended final scope of the framework.

---

## AI-Assisted Repair

ADEXA combines deterministic security-testing logic with AI-assisted decision making.

The AI layer is designed to support the following process:

```text
Broken Payload
      │
      ▼
Execution Context
      │
      ▼
Failure Analysis
      │
      ▼
Repair Strategy
      │
      ▼
Candidate Generation
      │
      ▼
Candidate Scoring
      │
      ▼
Execution
      │
      ▼
Verification
```

AI-assisted components can contribute to:

* interpreting failure information,
* selecting repair strategies,
* rewriting unsuccessful payloads,
* generating repair candidates,
* ranking candidates,
* and using previous successful cases as context.

ADEXA does not assume that an AI-generated candidate is correct simply because it appears syntactically valid.

**Verification is a core part of the architecture.**

---

## Repair Memory

ADEXA includes a repair-memory mechanism that can retain information from previous successful attempts.

The objective is to avoid treating every failure as an entirely new problem.

```text
Attempt
   ↓
Analyze
   ↓
Repair
   ↓
Verify
   ↓
Success
   ↓
Store
   ↓
Reuse When Relevant
```

This provides a foundation for ADEXA to make use of previous successful repair information during later executions.

---

## Project Structure

```text
ADEXA/
├── ai_engine/
│   ├── crash_ai.py
│   ├── exploit_rewriter.py
│   ├── exploit_scorer.py
│   ├── poc_ai.py
│   └── repair_memory.py
│
├── backends/
│   ├── binary_backend.py
│   └── web_backend.py
│
├── core/
│   ├── loop_controller.py
│   ├── models.py
│   └── run_store.py
│
├── dataset/
├── debugger/
│   ├── crash_parser.py
│   ├── gdb_runner.py
│   └── offset_finder.py
│
├── docs/
│   └── images/
│
├── exploit_tests/
├── gui/
├── poc_specs/
├── scripts/
│   └── setup_dvwa.sh
├── utils/
├── web_engine/
│
├── adexa.py
├── main.py
├── benchmark_adexa.py
├── compose.yml
├── requirements.txt
├── setup.sh
└── README.md
```

### Main Components

| Component        | Purpose                                                      |
| ---------------- | ------------------------------------------------------------ |
| `ai_engine/`     | AI-assisted analysis, repair generation, scoring, and memory |
| `backends/`      | Web and experimental binary execution backends               |
| `core/`          | Main adaptive loop, internal models, and run storage         |
| `dataset/`       | Dataset-related validation and evaluation tooling            |
| `debugger/`      | Crash parsing, GDB execution, and offset analysis            |
| `exploit_tests/` | Controlled local exploit-testing material                    |
| `poc_specs/`     | Proof-of-concept specifications                              |
| `web_engine/`    | Web vulnerability-analysis and processing components         |
| `gui/`           | Experimental graphical interface                             |
| `scripts/`       | Local laboratory setup scripts                               |
| `compose.yml`    | Docker-based DVWA and MariaDB laboratory                     |
| `setup.sh`       | Automated ADEXA and laboratory setup                         |

---

# Installation

## Prerequisites

ADEXA is currently developed and tested primarily on Linux/Kali Linux.

You will need:

* Python 3
* Git
* Docker
* Docker Compose

For experimental binary-analysis functionality:

* GDB

For supported local AI-assisted functionality:

* Ollama

---

## Quick Start

ADEXA includes an automated setup script that prepares the Python environment, installs dependencies, starts the local DVWA laboratory, and initializes its database.

### 1. Clone ADEXA

```bash
git clone https://github.com/David-Axel/Adexa.git
cd Adexa
```

### 2. Run the setup script

```bash
chmod +x setup.sh
./setup.sh
```

The script checks for Python, Git, Docker, and Docker Compose, creates the Python virtual environment, installs the required dependencies, starts the Docker-based DVWA laboratory, and initializes DVWA.

DVWA will be available locally at:

```text
http://127.0.0.1:4280
```

### 3. Check the environment

Before running a test, use ADEXA Doctor:

```bash
python3 adexa.py doctor
```

Doctor checks:

* Python,
* Python dependencies,
* Docker,
* Docker Compose,
* ADEXA setup files,
* and DVWA connectivity.

A healthy environment should show:

```text
✓ Python 3.13
✓ Python dependencies
✓ Docker is running
✓ Docker Compose
✓ ADEXA setup files
✓ DVWA is reachable

✓ ADEXA environment is ready.
```

### 4. Run the demonstration

```bash
python3 adexa.py demo
```

The demonstration runs a controlled SQL injection repair workflow against the local DVWA laboratory.

### 5. Start ADEXA

For beginners, use **Guided Mode**:

```bash
python3 adexa.py
```

For experienced users, use **Advanced Mode**:

```bash
python3 adexa.py \
  --url http://127.0.0.1:4280/vulnerabilities/sqli/ \
  --param id \
  --payload "'" \
  --method GET
```

> **Safety:** DVWA is intentionally vulnerable. The included laboratory is bound to `127.0.0.1` and should only be used for authorized security research, education, and controlled testing.

---

## Stop the Laboratory

When finished:

```bash
docker compose -f compose.yml down
```

---

# Usage

> **⚠️ Authorization Required:** The commands and examples below are intended only for systems you own or have explicit authorization to test.

## Guided Mode

Guided Mode is the recommended starting point for new users.

Run:

```bash
python3 adexa.py
```

ADEXA asks for the basic test configuration:

```text
Target URL:
Parameter [id]:
Initial payload [']:
HTTP method [GET]:
```

It then displays the configuration and asks for confirmation before starting the authorized test.

<p align="center">
  <img src="docs/images/adexa-guided-terminal.png"
       alt="ADEXA guided command-line interface"
       width="900">
</p>

<p align="center">
  <em>ADEXA guided CLI for configuring an authorized security test.</em>
</p>

Guided Mode keeps the interaction simple while still showing the user the important test configuration and final repair result.

---

## Advanced Mode

Experienced users can provide the configuration directly:

```bash
python3 adexa.py \
  --url http://127.0.0.1:4280/vulnerabilities/sqli/ \
  --param id \
  --payload "'" \
  --method GET
```

<img width="922" height="665" alt="Screenshot 2026-08-30 at 23 43 55" src="https://github.com/user-attachments/assets/886787ac-fe46-405f-8af7-82468f12181f" />


Advanced Mode provides more detailed execution information, including:

* candidate payloads,
* selected payload,
* selection reasoning,
* AI decision,
* repair-memory information,
* execution artifacts,
* and verification results.

---

## Environment Check

Use ADEXA Doctor to check whether the local environment is ready:

```bash
python3 adexa.py doctor
```

Doctor verifies the main components required by ADEXA before testing.

---

## Demonstration

Run the built-in controlled demonstration:

```bash
python3 adexa.py demo
```

The demonstration uses the local DVWA laboratory and shows:

1. the SQL injection test,
2. the original payload,
3. the failure analysis,
4. the repaired payload,
5. and verification of the repair.

---

# Web / SQL Injection Workflow

During a web execution, ADEXA can:

1. receive the initial payload and target configuration,
2. generate a temporary PoC specification,
3. execute the payload,
4. observe the target response,
5. analyze the unsuccessful attempt,
6. select a repair strategy,
7. generate a new candidate,
8. execute the candidate,
9. verify the result,
10. and store execution artifacts.

---

# Direct Core Execution

The lower-level execution engine can also be invoked directly:

```bash
python3 main.py <poc_spec.json> <web|binary>
```

Example:

```bash
python3 main.py poc_specs/dvwa_demo.json web
```

For normal interaction with ADEXA, `adexa.py` should generally be used instead.

---

# Benchmark

ADEXA includes a benchmark script for evaluating the current repair pipeline:

```bash
python3 benchmark_adexa.py
```

The benchmark can be used to analyze characteristics such as:

* repair success,
* verification success,
* payload-family preservation,
* strategy selection,
* memory usage,
* repair quality,
* and candidate diversity.

---

# Testing

ADEXA uses `pytest` for automated testing.

Run the test suite with:

```bash
python3 -m pytest -q
```

The test suite covers areas including:

* SQL injection repair strategies,
* candidate generation,
* candidate scoring,
* payload normalization,
* repair-memory behavior,
* and web request parsing.

Some tests may require the local DVWA laboratory.

Start DVWA with:

```bash
docker compose -f compose.yml up -d
```

Then run:

```bash
python3 -m pytest -q
```

---

# Execution Logs

ADEXA creates structured execution artifacts for individual runs.

Runtime information is stored under:

```text
runs/
```

Depending on the execution, these artifacts can contain information about:

```text
Run
├── Original Payload
├── Observation
├── Failure Information
├── AI Decision
├── Repair Strategy
├── Candidate Payload
├── Verification Result
└── Final State
```

Runtime-generated files are excluded from Git through `.gitignore`.

This keeps development artifacts separate from the public source repository.

---

# Experimental Binary Support

ADEXA also contains experimental components for binary exploit analysis and repair.

These components investigate:

* debugger integration,
* crash analysis,
* offset discovery,
* exploit rewriting,
* candidate execution,
* and verification.

Binary support remains experimental and is not currently the primary development focus.

---

# Evaluation

ADEXA is evaluated on more than whether it can simply produce another payload.

Important evaluation metrics include:

* repair success rate,
* verification success rate,
* payload-family preservation,
* number of repair iterations,
* repair-memory usage,
* candidate diversity,
* repair quality,
* and performance on previously unseen cases.

A major development objective is to evaluate whether ADEXA's AI-assisted repair capabilities materially outperform simpler repair approaches on **held-out, unseen SQL injection cases**.

---

# Roadmap

ADEXA is currently transitioning from a university research prototype toward a broader adaptive security-testing framework.

## SQL Injection

* [x] Adaptive execution loop
* [x] SQLi repair pipeline
* [x] Boolean-based verification
* [x] Time-based verification
* [x] Repair memory
* [x] Benchmark framework
* [x] Reproducible local DVWA laboratory
* [x] Basic automated test suite
* [x] Guided CLI
* [x] Environment Doctor
* [x] Built-in demonstration
* [ ] Expand SQLi training dataset
* [ ] Evaluate on completely unseen payloads
* [ ] Improve repair strategy classification
* [ ] Improve candidate diversity
* [ ] Benchmark AI-assisted repair against baseline approaches

## Platform

* [x] Automated setup script
* [x] Docker-based local laboratory
* [x] Guided CLI
* [x] Advanced CLI
* [x] Environment Doctor
* [x] Built-in demonstration
* [ ] Improve reporting
* [ ] Simplify installation and configuration
* [ ] Develop a more complete user interface
* [ ] Add scanner integrations
* [ ] Add automated remediation re-testing
* [ ] Improve automated testing
* [ ] Improve contributor workflow

## Future Vulnerability Classes

Potential future research includes:

* Cross-Site Scripting (XSS)
* Command Injection
* Server-Side Request Forgery (SSRF)
* additional web vulnerability classes

---

# Long-Term Vision

ADEXA's long-term objective extends beyond SQL injection payload repair.

The broader workflow being explored is:

```text
Security Finding
       │
       ▼
Exploit Attempt
       │
       ▼
Observe Result
       │
       ▼
Failure Analysis
       │
       ▼
Adaptive Repair
       │
       ▼
Exploit Verification
       │
       ▼
Evidence
       │
       ▼
Remediation
       │
       ▼
Security Re-Test
```

The goal is to investigate how **adaptive reasoning, execution, memory, and verification** can reduce repetitive manual work during authorized security testing.

---

# Responsible Use

ADEXA is intended exclusively for:

* cybersecurity research,
* educational environments,
* controlled laboratories,
* CTF-style environments,
* vulnerability research,
* and systems where the tester has explicit authorization.

The included DVWA environment is intentionally vulnerable and exists solely for controlled security research and development.

**Do not use ADEXA against systems without permission.**

Users are responsible for ensuring that their activities comply with applicable laws, policies, and authorization requirements.

---

# License

ADEXA is distributed under the terms provided in the [`LICENSE`](LICENSE) file.

---

# Author

**David-Axel Kacou**

Cybersecurity & Digital Forensics

---

> ADEXA is an experimental research project under active development and should not currently be considered a production-ready penetration-testing platform.

```
```

# TIM

TIM is a self-hosted threat intelligence management platform built around
OpenCTI 7. It extends the OpenCTI knowledge graph with ingestion, analysis,
search, and reporting workflows designed for operational CTI teams.

Its two distinguishing capabilities are:

- extracting structured CTI from non-STIX sources such as PDFs and web pages;
- producing executive briefings whose identifiers are checked against the
  source context before publication.

Inference can run locally through Ollama or use AWS Bedrock when the selected
deployment target and data-handling policy permit it.

## Architecture

OpenCTI remains the system of record and STIX 2.1 knowledge graph. TIM adds
small services around it:

| Service | Responsibility |
| --- | --- |
| `feed-orchestrator` | Fetches, normalizes, deduplicates, and exports structured feeds as STIX 2.1. |
| `intel-extractor` | Converts PDFs and URLs into cited IOCs, entities, techniques, and relationships. |
| `semantic-engine` | Indexes CTI in ChromaDB and provides vector search linked back to OpenCTI objects. |
| `briefing-generator` | Creates persistent, exportable briefings and verifies identifiers against context. |
| `dashboard` | Provides analyst views for overview, hunting, briefings, alerts, and ingestion. |
| `connector-cve` | Adapts CVE ingestion for the platform deployment. |
| `connector-greynoise-feed` | Adapts GreyNoise feed ingestion. |

The Compose stack supplies OpenCTI, Elasticsearch, Redis, RabbitMQ, MinIO,
connectors, Ollama, ChromaDB, Kibana, and the TIM services. Two overlays select
the intended runtime:

- `local-gpu` for local inference with NVIDIA acceleration;
- `aws` for the AWS-oriented deployment profile.

The main data path is:

```text
structured feeds ──> feed-orchestrator ──┐
                                         ├──> OpenCTI ──> semantic search
PDFs and URLs ────> intel-extractor ─────┘            └──> verified briefings
                                                                  │
                                                    dashboard and Kibana
```

## Quickstart

Clone the repository, enter its root, and generate a local environment file:

```bash
./scripts/setup-env.sh
```

Review `.env` and add any optional provider or feed API keys you intend to
use. Real secrets belong only in `.env`; never commit that file.

Start the local GPU target:

```bash
./scripts/bootstrap-platform.sh local-gpu
```

The bootstrap starts the core dependencies first, waits for the OpenCTI graph
and MITRE ATT&CK data, then starts the remaining profiles and runs functional
checks.

Run the readiness gate again at any time:

```bash
./scripts/tim-check.sh local-gpu
```

For the AWS target, use the same sequence with `aws`:

```bash
./scripts/bootstrap-platform.sh aws
./scripts/tim-check.sh aws
```

## Repository layout

| Path | Contents |
| --- | --- |
| `services/` | TIM services, connector adaptations, dashboards, and service tests. |
| `scripts/` | Environment setup, bootstrap, operations, backup, and verification tools. |
| `docs/` | User, deployment, design, diagnostic, and use-case documentation. |
| `experiments/` | Reproducible protocols, harnesses, code, tests, manifests, metrics, and project results. |
| `corpus/` | Evaluation tools, provenance manifests, reference data, hashes, and system outputs. |
| `tesis/tesis.pdf` | The research thesis describing and evaluating TIM. |

## Experimental material and provenance

The experiment directories preserve the code, frozen parameters, structured
references, generated outputs, and scoring artifacts needed to inspect the
reported results. They do not bundle complete third-party articles or advisory
documents.

Third-party source documents are referenced by their original URLs and
SHA-256 hashes. This keeps the provenance auditable without republishing
material whose redistribution terms may differ from the code license. See the
manifests beside each experiment and [`corpus/SOURCES.md`](corpus/SOURCES.md).

Some recorded outputs contain harmless threat-intelligence indicators,
including domains and URLs. Treat them as research data, not as links to open
in a browser.

## Thesis and licensing

The [thesis](tesis/tesis.pdf) is in Spanish and is provided for reading under
All Rights Reserved. Source code and original repository documentation are
licensed under the [MIT License](LICENSE).

Third-party names, data, and structured references remain subject to their
respective owners' terms. Inclusion of a URL or hash does not grant additional
rights to the referenced work.

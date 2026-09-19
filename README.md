# TIM

TIM is a self-hosted threat intelligence management platform built around
OpenCTI 7. It extends the OpenCTI knowledge graph with ingestion, analysis,
search, and reporting workflows designed for operational CTI teams.

Its two distinguishing capabilities are:

- extracting structured CTI from non-STIX sources such as PDFs and web pages;
- producing executive briefings whose identifiers are checked against the
  source context before publication.

Generation runs on Amazon Bedrock (Claude), authenticated by the instance IAM
role. Documents sent for extraction therefore leave the host: review your
data-handling policy before ingesting restricted material.

## Architecture

OpenCTI remains the system of record and STIX 2.1 knowledge graph. TIM adds
small services around it:

| Service | Responsibility |
| --- | --- |
| `feed-orchestrator` | Fetches, normalizes, deduplicates, and exports structured feeds as STIX 2.1. |
| `intel-extractor` | Converts PDFs and URLs into cited IOCs, entities, techniques, and relationships. |
| `briefing-generator` | Creates persistent, exportable briefings and verifies identifiers against context. |
| `dashboard` | Provides analyst views for overview, briefings, alerts, and ingestion. |
| `connector-cve` | Adapts CVE ingestion for the platform deployment. |
| `connector-greynoise-feed` | Adapts GreyNoise feed ingestion. |

The Compose stack supplies OpenCTI, Elasticsearch, Redis, RabbitMQ, MinIO,
connectors, Kibana, and the TIM services. It targets a single environment: an
AWS node without a GPU (`aws`). The local GPU pilot that ran generation through
Ollama was retired; the `pre-fase3-evidencia` git tag is the last revision
that contains it.

The main data path is:

```text
structured feeds ──> feed-orchestrator ──┐
                                         ├──> OpenCTI ──> verified briefings
PDFs and URLs ────> intel-extractor ─────┘                      │
                                                    dashboard and Kibana
```

## Quickstart

Clone the repository, enter its root, and generate a local environment file:

```bash
./scripts/setup-env.sh
```

Review `.env` and add any optional provider or feed API keys you intend to
use. Real secrets belong only in `.env`; never commit that file.

Generate local TLS certificates for the dashboard reverse proxy (one-time,
requires [mkcert](https://github.com/FiloSottile/mkcert) — see `certs/README.md`):

```bash
mkcert -install
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1
```

Start the platform:

```bash
./scripts/bootstrap-platform.sh aws
```

The bootstrap starts the core dependencies first, waits for the OpenCTI graph
and MITRE ATT&CK data, then starts the remaining profiles and runs functional
checks.

Run the readiness gate again at any time:

```bash
./scripts/tim-check.sh aws
```

The host needs an IAM role allowed to invoke the Bedrock model named by
`BEDROCK_MODEL` in `AWS_REGION`; no API key is stored anywhere.

## Repository layout

| Path | Contents |
| --- | --- |
| `services/` | TIM services, connector adaptations, dashboards, and service tests. |
| `scripts/` | Environment setup, bootstrap, operations, backup, and verification tools. |
| `docs/` | User, deployment, design, diagnostic, and use-case documentation. |
| `experiments/` | Reproducible protocols, harnesses, code, tests, manifests, metrics, and project results. |
| `corpus/` | Evaluation tools, provenance manifests, reference data, hashes, and system outputs. |

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

## Licensing

Source code and original repository documentation are licensed under the
[MIT License](LICENSE). The research thesis that describes and evaluates TIM is
not distributed with this repository.

Third-party names, data, and structured references remain subject to their
respective owners' terms. Inclusion of a URL or hash does not grant additional
rights to the referenced work.

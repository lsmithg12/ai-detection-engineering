# Third-Party Software Licenses

This project references and orchestrates several third-party tools via Docker.
**No third-party binaries are redistributed** in this repository — Docker pulls
official images at runtime. You are responsible for reviewing and accepting
each product's license terms.

---

## Elasticsearch & Kibana (Elastic Stack)

- **Image**: `docker.elastic.co/elasticsearch/elasticsearch:8.17.0`
- **Image**: `docker.elastic.co/kibana/kibana:8.17.0`
- **License**: [Elastic License 2.0 (ELv2)](https://www.elastic.co/licensing/elastic-license)
- **Usage**: Free for internal use, development, and education
- **Restrictions**:
  - You may NOT provide the products to others as a managed service
  - You may NOT circumvent license key functionality
  - You may NOT remove licensing or copyright notices
- **FAQ**: https://www.elastic.co/licensing/elastic-license/faq

## Elastic MCP Server

- **Image**: `docker.elastic.co/mcp/elasticsearch`
- **License**: [Elastic License 2.0 (ELv2)](https://www.elastic.co/licensing/elastic-license)
- **Usage**: Same terms as Elasticsearch above

## Splunk Enterprise

- **Image**: `splunk/splunk:9.3`
- **License**: [Splunk General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html)
- **Usage**: Free tier allows up to 500 MB/day indexing (never expires)
- **Note**: By setting `SPLUNK_START_ARGS=--accept-license` in docker-compose.yml,
  you accept Splunk's license terms. Review them before running.
- **Docker repo license**: [Apache License 2.0](https://github.com/splunk/docker-splunk/blob/develop/LICENSE)
  (applies to the Docker build tooling, not Splunk itself)

## Cribl Stream

- **Image**: `cribl/cribl:latest`
- **License**: Proprietary — [Cribl Subscription Services Agreement](https://cribl.io/legal/cribl-subscription-services-agreement/)
- **Usage**: Free tier allows up to 1 TB/day processing (single worker group)
- **Restrictions**:
  - You may NOT sell, re-sell, rent, lease, transfer, or distribute the software
  - Free tier requires sending anonymized telemetry to Cribl
  - Community support only on free tier
- **Note**: This project does NOT redistribute Cribl. Docker pulls the image
  directly from Cribl's registry at runtime.

## sigma-cli (pySigma)

- **Package**: `sigma-cli` (installed via pip)
- **License**: [LGPL-2.1](https://github.com/SigmaHQ/pySigma/blob/main/LICENSE) (pySigma core)
- **Backends**: Individual backends (elasticsearch, splunk) may have separate licenses (typically MIT)
- **Usage**: Free and open source

## Fawkes C2 Agent (Reference Only)

- **Repository**: https://github.com/galoryber/fawkes
- **License**: [BSD 3-Clause](https://github.com/galoryber/fawkes/blob/main/LICENSE)
- **Note**: Fawkes source code is NOT included in this project. The `threat-intel/`
  directory contains only behavioral analysis and MITRE ATT&CK mappings derived
  from public documentation.

## GitHub MCP Server

- **Package**: `@modelcontextprotocol/server-github`
- **License**: [MIT](https://github.com/modelcontextprotocol/servers/blob/main/LICENSE)

## curl (init container)

- **Image**: `curlimages/curl:latest`
- **License**: [MIT/X-derivative](https://curl.se/docs/copyright.html)
- **Usage**: Used as an init container to configure Elasticsearch security

---

## Your Responsibilities

By using this project, you agree to:

1. **Review** each product's license before running `docker compose up`
2. **Accept** Splunk's license terms (automated via `--accept-license`)
3. **Not use** this project to provide Elastic, Splunk, or Cribl as a managed service to third parties
4. **Comply** with all applicable license terms for your use case
5. **Use** the Fawkes C2 threat intelligence for **defensive purposes only**

## Questions?

If you have licensing questions about a specific component, refer to the
vendor's official documentation linked above.

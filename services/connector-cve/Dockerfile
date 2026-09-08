# ponytail: ARG en vez de version fija — el portatil corre 7.260706.0 y el host
# AWS 7.260803.0, y el conector debe ir a la par de su plataforma. El defecto
# deja el comportamiento local intacto; docker-compose.aws.yml lo sobreescribe.
# Verificado el 2026-08-07: cve_connector.py es IDENTICO en ambas versiones, asi
# que el overlay de abajo aplica igual. Volver a comprobarlo al subir de version.
ARG OPENCTI_VERSION=7.260706.0
FROM opencti/connector-cve:${OPENCTI_VERSION}
# Rolling 7.x rewrote the NVD client to async aiohttp — the old api.py overlay
# (retry/timeout patches) is superseded upstream and no longer applied.
COPY constants.py /opt/opencti-connector-cve/src/services/utils/constants.py
COPY cveConnector.py /opt/opencti-connector-cve/src/connector/cve_connector.py

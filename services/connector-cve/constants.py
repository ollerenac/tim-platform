from pathlib import Path

CONFIG_FILE_PATH = Path(__file__).parents[2].joinpath("config.yml")
# ponytail: 30 days instead of upstream 120 — NVD times out on 120-day payloads (~20k CVEs)
MAX_AUTHORIZED = 30

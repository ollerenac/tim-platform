FROM opencti/connector-greynoise-feed:7.260706.0
# Overlay patch: upstream parses last_seen_timestamp with "%Y-%m-%dT%H:%M:%SZ"
# but the Feed API returns space-separated "YYYY-MM-DD HH:MM:SS", aborting every
# import at connector.py:193. Remove this overlay once fixed upstream.
# Second overlay: upstream re-imports the whole feed on every container start, because pycti's
# scheduler fires at start and the connector never checks its own last_run_timestamp.
# schedule_guard.py skips a start that follows a recent run (self-check: python3 schedule_guard.py).
COPY connector.py schedule_guard.py /opt/greynoise-feed/connector/

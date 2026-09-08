FROM opencti/connector-greynoise-feed:7.260706.0
# Overlay patch: upstream parses last_seen_timestamp with "%Y-%m-%dT%H:%M:%SZ"
# but the Feed API returns space-separated "YYYY-MM-DD HH:MM:SS", aborting every
# import at connector.py:193. Remove this overlay once fixed upstream.
COPY connector.py /opt/greynoise-feed/connector/connector.py

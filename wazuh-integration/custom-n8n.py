#!/usr/bin/env python3
import sys
import json
import urllib.request

def main():
    alert_file = sys.argv[1]
    hook_url = sys.argv[3]

    with open(alert_file) as f:
        alert = json.load(f)

    payload = {
        "rule_id": alert.get("rule", {}).get("id"),
        "rule_description": alert.get("rule", {}).get("description"),
        "level": alert.get("rule", {}).get("level"),
        "agent_name": alert.get("agent", {}).get("name"),
        "agent_id": alert.get("agent", {}).get("id"),
        "full_log": alert.get("full_log"),
        "timestamp": alert.get("timestamp"),
        "location": alert.get("location"),
        "data": alert.get("data", {}),
        "syscheck": alert.get("syscheck", {}),
        "syscheck": alert.get("syscheck", {}),
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        hook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        sys.stderr.write(f"Failed to send alert to n8n: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()

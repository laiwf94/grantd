#!/usr/bin/env bash
# Walks through grantd against a running server.
#   GRANTD_URL (default http://localhost:8080), GRANTD_API_KEY (default local-dev-key-0123456)
set -euo pipefail

URL="${GRANTD_URL:-http://localhost:8080}"
KEY="${GRANTD_API_KEY:-local-dev-key-0123456}"
DIR="$(cd "$(dirname "$0")" && pwd)"

call() { # method path json
  curl -fsS -X "$1" "$URL$2" -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' -d "$3"
}
field() { python3 -c "import sys, json; v = json.load(sys.stdin)['$1']; print(json.dumps(v) if isinstance(v, bool) else v)"; }

echo "1. Write the schema"
schema_json=$(python3 -c 'import json, sys; print(json.dumps({"schema": open(sys.argv[1]).read()}))' "$DIR/docs.schema")
call PUT /v1/schema "$schema_json" > /dev/null

echo "2. Write relationships"
written=$(call POST /v1/relationships/write '{"updates":[
  {"op":"touch","relationship":"group:eng#member@user:alice"},
  {"op":"touch","relationship":"group:staff#member@group:eng#member"},
  {"op":"touch","relationship":"group:staff#member@user:carol"},
  {"op":"touch","relationship":"folder:root#viewer@group:staff#member"},
  {"op":"touch","relationship":"folder:specs#parent@folder:root"},
  {"op":"touch","relationship":"doc:design#parent@folder:specs"},
  {"op":"touch","relationship":"doc:design#editor@group:eng#member"}
]}' | field written_at)

check() { # resource permission subject token
  allowed=$(call POST /v1/check "{\"resource\":\"$1\",\"permission\":\"$2\",\"subject\":\"$3\",
    \"consistency\":{\"mode\":\"at_least_as_fresh\",\"token\":\"$4\"}}" | field allowed)
  printf '   %-12s %-5s %-12s -> %s\n' "$1" "$2" "$3" "$allowed"
}

echo "3. Check, at least as fresh as that write"
check doc:design edit user:alice "$written"
check doc:design view user:carol "$written"
check doc:design edit user:carol "$written"

echo "4. Ban carol, then check with the new token (no new-enemy window)"
banned=$(call POST /v1/relationships/write '{"updates":[{"op":"touch","relationship":"doc:design#banned@user:carol"}]}' | field written_at)
check doc:design view user:carol "$banned"

echo "5. Which docs can alice view?"
call POST /v1/lookup/resources '{"resource_type":"doc","permission":"view","subject":"user:alice","consistency":{"mode":"fully_consistent"}}'
echo

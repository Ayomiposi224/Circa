#!/bin/sh
set -eu

# Read one value from .env without sourcing the whole file
get() { grep "^$1=" .env | cut -d= -f2-; }

for pair in \
  cyberwatch_app:CIRCA_DB_PASSWORD \
  cyberwatch_readonly:CIRCA_DB_RO_PASSWORD \
  cyberwatch_unsub:CIRCA_DB_UNSUB_PASSWORD \
  cyberwatch_signup:CIRCA_DB_SIGNUP_PASSWORD \
  cyberwatch_lookup:CIRCA_DB_LOOKUP_PASSWORD
do
  role=${pair%%:*}
  var=${pair#*:}
  value=$(get "$var")
  [ -n "$value" ] || { echo "Missing $var in .env" >&2; exit 1; }
  printf "ALTER ROLE %s PASSWORD '%s';\n" "$role" "$value" |
    docker compose exec -T db psql -U postgres -d cyberwatch -v ON_ERROR_STOP=1
done

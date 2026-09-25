#!/bin/bash
set -e
# Create the separate Temporal database alongside the app database.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
  SELECT 'CREATE DATABASE temporal' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'temporal')\gexec
SQL

#!/bin/bash
set -e
# Create separate Temporal history and visibility databases alongside the app database.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-SQL
  SELECT 'CREATE DATABASE temporal' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'temporal')\gexec
  SELECT 'CREATE DATABASE temporal_visibility' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'temporal_visibility')\gexec
SQL

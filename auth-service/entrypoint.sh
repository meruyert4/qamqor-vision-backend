#!/bin/sh
set -e

echo "⏳ Waiting for PostgreSQL to be ready..."
until pg_isready -h postgres -U user -d authdb > /dev/null 2>&1; do
  sleep 1
done

echo "✅ PostgreSQL is ready, running migrations..."
for f in ./internal/migrations/*.up.sql; do
  echo "Applying migration: $f"
  PGPASSWORD=password psql -h postgres -U user -d authdb -q -f "$f" || true
done

echo "🚀 Starting auth-service..."
exec ./auth-service

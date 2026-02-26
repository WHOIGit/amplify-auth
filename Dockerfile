FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Copy package files
COPY pyproject.toml README.md ./
COPY amplify_auth ./amplify_auth

# Copy database schema
COPY schema.sql /app/schema.sql

# Install package with server extras
RUN pip install --no-cache-dir ".[server]"

# Run the auth server
CMD ["amplify-auth-server"]

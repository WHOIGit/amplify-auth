# amplify-auth

Bearer token authentication client and server for AMPLIfy services.

## Install

Client only:
```bash
pip install amplify-auth
```

With server dependencies:
```bash
pip install "amplify-auth[server]"
```

## Client usage

```python
from amplify_auth import AuthClient
from fastapi import Depends, FastAPI

app = FastAPI()
auth = AuthClient("http://auth-service:8000")

@app.get("/protected")
async def protected(token_info=Depends(auth.require_scopes(["read"]))):
    return {"user": token_info.name}
```

## Running the auth server

```bash
docker compose up
```

Requires `ADMIN_TOKEN` in the environment (or a `.env` file). See `docker-compose.yml` for all options.

## Managing tokens (CLI)

Set `ADMIN_TOKEN` and point at a running auth server:

```bash
export ADMIN_TOKEN=your-admin-token
export AUTH_URL=http://localhost:8000  # optional, this is the default

# Create a token
amplify-auth-cli create my-service --scopes read write --ttl 365

# List tokens
amplify-auth-cli list

# Get details for a specific token
amplify-auth-cli info <token-id>

# Revoke a token
amplify-auth-cli revoke <token-id>
```

## Development

```bash
pip install -e ".[server,test]"
pytest
```

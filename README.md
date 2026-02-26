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

## Development

```bash
pip install -e ".[server,test]"
pytest
```

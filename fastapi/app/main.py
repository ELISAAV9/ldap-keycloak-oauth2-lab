import os
import httpx
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from jose import jwt, JWTError
from starlette.middleware.base import BaseHTTPMiddleware
 
KC_INTERNAL=os.getenv("KEYCLOAK_INTERNAL","http://keycloak:8080")
KC_PUBLIC=os.getenv("KEYCLOAK_PUBLIC","http://localhost:8081")
REALM=os.getenv("KEYCLOAK_REALM","cybersecurity")
CLIENT_ID=os.getenv("KEYCLOAK_CLIENT_ID","fastapi-api")
ISSUER=f"{KC_PUBLIC}/realms/{REALM}"
JWKS_URL=f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/certs"
 
oauth2_scheme=OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{ISSUER}/protocol/openid-connect/auth",
    tokenUrl=f"{ISSUER}/protocol/openid-connect/token",
    scopes={"openid":"OpenID Connect identity"},
)
 
ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
DOCS_ENABLED = ENVIRONMENT == "development"
 
app = FastAPI(
    title="LDAP + OAuth 2.0 / OIDC API",
    version="2.0.0",
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)
 
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response
 
app.add_middleware(SecurityHeadersMiddleware)
 
@app.get("/health")
def health(): return {"status":"ok"}
 
async def current_user(token: Annotated[str,Depends(oauth2_scheme)]):
    try:
        async with httpx.AsyncClient() as c:
            r=await c.get(JWKS_URL,timeout=5); r.raise_for_status()
            jwks=r.json()
        header=jwt.get_unverified_header(token)
        key=next((k for k in jwks["keys"] if k.get("kid")==header.get("kid")),None)
        if not key: raise HTTPException(401,"Signing key not found")
        return jwt.decode(token,key,algorithms=["RS256"],audience=CLIENT_ID,issuer=ISSUER)
    except (JWTError,httpx.HTTPError,StopIteration) as e:
        raise HTTPException(401,f"Invalid access token: {e}",headers={"WWW-Authenticate":"Bearer"})
 
@app.get("/api/profile")
async def profile(user: Annotated[dict,Depends(current_user)]):
    return {"message":"OAuth 2.0 access token accepted","subject":user.get("sub"),
            "username":user.get("preferred_username"),"email":user.get("email"),"issuer":user.get("iss")}


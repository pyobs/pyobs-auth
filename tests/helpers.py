from __future__ import annotations

import json
from dataclasses import dataclass

import jwt
import responses
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User

ISSUER = "https://keycloak.example.org/realms/pyobs"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
AUTHORIZATION_ENDPOINT = f"{ISSUER}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
USERINFO_ENDPOINT = f"{ISSUER}/protocol/openid-connect/userinfo"
END_SESSION_ENDPOINT = f"{ISSUER}/protocol/openid-connect/logout"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
KID = "test-key-1"


def resolve_user(claims: dict) -> User:
    """Test USER_RESOLVER: joins on the `sub` claim, stored (for test purposes only) in username."""
    user, _ = User.objects.get_or_create(username=claims["sub"])
    return user


def resolve_user_or_reject(claims: dict) -> User | None:
    """Test USER_RESOLVER variant: returns None (e.g. a resolver-side rejection unrelated to the
    claims gate, such as a disallowed email domain) when the claims carry `email ==
    "reject@example.org"`, otherwise behaves like `resolve_user` above."""
    if claims.get("email") == "reject@example.org":
        return None
    return resolve_user(claims)


@dataclass
class SigningKeys:
    private_key: rsa.RSAPrivateKey
    jwks: dict

    def sign(self, claims: dict) -> str:
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": KID})


def generate_signing_keys() -> SigningKeys:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = KID
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"

    return SigningKeys(private_key=private_key, jwks={"keys": [jwk]})


def register_discovery_and_jwks(mock: responses.RequestsMock, keys: SigningKeys, monkeypatch) -> None:
    mock.get(
        DISCOVERY_URL,
        json={
            "issuer": ISSUER,
            "authorization_endpoint": AUTHORIZATION_ENDPOINT,
            "token_endpoint": TOKEN_ENDPOINT,
            "userinfo_endpoint": USERINFO_ENDPOINT,
            "end_session_endpoint": END_SESSION_ENDPOINT,
            "jwks_uri": JWKS_URI,
        },
    )
    # PyJWKClient fetches JWKS via urllib.request, not `requests` - `responses` can't see that
    # call, so it's monkeypatched directly instead of mocked at the HTTP layer.
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", lambda self: keys.jwks)

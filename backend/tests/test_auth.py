import uuid
import pytest

from services.auth_service import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)


class _User:
    def __init__(self, email: str, role):
        self.id = uuid.uuid4()
        self.email = email
        self.role = role


def test_password_roundtrip():
    h = hash_password("SuperSecret123!")
    assert verify_password("SuperSecret123!", h)
    assert not verify_password("wrong", h)


def test_access_token_contains_role_and_typ():
    from models_sql.user import UserRole
    user = _User("zeineb@example.com", UserRole.ANALYST)
    tok = create_access_token(user)
    payload = decode_token(tok)
    assert payload["typ"] == "access"
    assert payload["role"] == "analyst"
    assert payload["email"] == "zeineb@example.com"


def test_refresh_token_has_different_typ():
    from models_sql.user import UserRole
    user = _User("z@e.com", UserRole.ADMIN)
    payload = decode_token(create_refresh_token(user))
    assert payload["typ"] == "refresh"


def test_invalid_token_raises():
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        decode_token("not.a.jwt")

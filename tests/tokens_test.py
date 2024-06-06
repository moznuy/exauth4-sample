import base64
import uuid
from unittest.mock import patch

import pytest
import redis

from exauth import app
from exauth import EXAUTH_AUTH_HEADER
from exauth import EXAUTH_AUTH_TOKENS_KEY


@pytest.fixture
def client():
    return app.test_client()


@pytest.fixture
def redis_client():
    cl = redis.StrictRedis(db=2, decode_responses=True)
    cl.flushdb()
    yield cl
    cl.flushdb()


@pytest.fixture
def valid_creds(redis_client):
    creds_uuid = uuid.uuid4()
    unct = uuid.uuid4()
    creds = base64.urlsafe_b64encode(creds_uuid.bytes).decode()
    headers = {EXAUTH_AUTH_HEADER: creds}
    redis_client.hset(EXAUTH_AUTH_TOKENS_KEY, str(creds_uuid), str(unct))
    return headers, unct


def test_request_example(client, redis_client, valid_creds):
    headers, unct = valid_creds
    room_name = "test_room"
    with patch("exauth.redis_client", redis_client):
        response = client.post(
            "/token/v2/", headers=headers, json={"room_name": room_name}
        )
        streaming_token1 = response.json["streaming_token"]

        response = client.post(
            "/token/v2/", headers=headers, json={"room_name": room_name}
        )
        streaming_token2 = response.json["streaming_token"]
        assert streaming_token1 == streaming_token2

import base64
import dataclasses
import datetime
import logging
import os
import pprint
import uuid
from typing import Any
from typing import Mapping
from typing import Optional
from typing import Protocol
from typing import Tuple

import jwt
import redis
from dotenv import load_dotenv
from flask import abort
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask.typing import ResponseReturnValue
from flask_cors import cross_origin
from flask_httpauth import HTTPBasicAuth
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

load_dotenv()

REDIS_HOST = os.environ["REDIS_HOST"]
REDIS_PORT = int(os.environ["REDIS_PORT"])
REDIS_DB = int(os.environ["REDIS_DB"])
BASICAUTH_USERNAME = os.environ["BASICAUTH_USERNAME"]
BASICAUTH_PASSWORD = os.environ["BASICAUTH_PASSWORD"]
CLUSTER_REF = os.environ["CLUSTER_REF"]
SHARED_SECRET = os.environ["SHARED_SECRET"]
STREAMING_TOKEN_EXPIRATION_TIME = datetime.timedelta(minutes=60 * 4)
STREAMING_TOKEN_TEST_EXPIRATION_TIME = datetime.timedelta(seconds=20)
EXAUTH_AUTH_HEADER = "Auth-Token"
EXAUTH_AUTH_TOKENS_KEY = "EXAUTH_AUTH_TOKENS"


logging.basicConfig(
    format="%(asctime)s - %(name)20s:%(lineno)3d - %(levelname)-8s: %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
)
# Try this later instead https://flask-httpauth.readthedocs.io/en/latest/#digest-authentication-example
auth = HTTPBasicAuth()
users = {
    BASICAUTH_USERNAME: generate_password_hash(
        BASICAUTH_PASSWORD, method="pbkdf2:sha256:2000", salt_length=2
    )
}
logger.debug("ENV: %s", pprint.pformat(list(os.environ.items())))


@auth.verify_password
def verify_password(username: str, password: str) -> Optional[str]:
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None


def authenticate() -> uuid.UUID:
    token_b64 = request.headers.get(EXAUTH_AUTH_HEADER)
    if not token_b64:
        abort(401)

    token = None
    try:
        token = uuid.UUID(bytes=base64.urlsafe_b64decode(token_b64))
    except (TypeError, ValueError):
        abort(401)

    unct = redis_client.hget(EXAUTH_AUTH_TOKENS_KEY, str(token))
    if not unct:
        abort(401)

    try:
        return uuid.UUID(unct)
    except (TypeError, ValueError):
        abort(401)


def _now() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


class TokenCreation(Protocol):
    def __call__(
        self, unct: uuid.UUID, key: str, ex: datetime.timedelta, cluster_ref: str
    ) -> str:
        ...


# From CAS fast path
def generate_token_v2(
    unct: uuid.UUID,
    key: str,
    ex: datetime.timedelta = STREAMING_TOKEN_EXPIRATION_TIME,
    cluster_ref: str = CLUSTER_REF,
) -> str:
    now = _now()
    exp = now + ex

    payload = {
        "rid": str(uuid.uuid4()),
        "unct": str(unct),
        "grout": f"https://grout.{cluster_ref}.XXXXXX/api/select",
        "env": "prod",
        "exp": exp,
    }
    return jwt.encode(payload=payload, key=key)


# From CAS fast path
# TODO: similar code
def sync_service_token(
    unct: uuid.UUID,
    key: str,
    ex: datetime.timedelta = STREAMING_TOKEN_EXPIRATION_TIME,
    cluster_ref: str = CLUSTER_REF,
) -> str:
    now = _now()
    exp = now + ex

    payload = {
        "rid": str(uuid.uuid4()),
        "unct": str(unct),
        "host": f"sync.{cluster_ref}.XXXXXX",
        "exp": exp,
    }

    return jwt.encode(payload=payload, key=key)


mapping: Mapping[Tuple[str, str], TokenCreation] = {
    ("token", "v2"): generate_token_v2,
    ("sync", "v2"): sync_service_token,
}


@app.route("/<service>/<version>/", methods=["POST"])
@cross_origin(
    origins=[
        r"^https:\/\/([\w-]+\.)?([\w-]+\.)XXXXXX\.com$",
        r"^https?:\/\/localhost(:\d+)?$",
    ]
)
def get_or_create_token(service: str, version: str) -> ResponseReturnValue:
    func = mapping.get((service, version))
    if func is None:
        abort(404)

    unct = authenticate()
    payload: Mapping[str, Any] = request.get_json()
    room_name = payload.get("room_name")
    if not room_name:
        abort(400)

    is_test_token = payload.get("test") is True
    ex = (
        STREAMING_TOKEN_TEST_EXPIRATION_TIME
        if is_test_token
        else STREAMING_TOKEN_EXPIRATION_TIME
    )
    # TODO: remove hardcode; move to redis
    if str(unct) == "63bd399c-c681-483e-964d-7321bcb71653":
        ex = datetime.timedelta(hours=12)

    cluster_ref = CLUSTER_REF
    try:
        cluster_ref = request.host.split(":")[0].split(".")[1]
    except IndexError:
        logger.error("Error getting cluster_ref from host: %s", request.host)

    new_streaming_token = func(
        unct=unct, key=SHARED_SECRET, ex=ex, cluster_ref=cluster_ref
    )
    with redis_client.pipeline(transaction=True) as transaction:
        key = f"EXAUTH_TOKEN_{unct!s}_{service}_{cluster_ref}_{version}_{room_name}"
        transaction.set(key, new_streaming_token, ex=ex, nx=True)
        transaction.get(key)
        _, streaming_token = transaction.execute()
    return jsonify({"streaming_token": streaming_token})


@dataclasses.dataclass
class TokenInfo:
    token: str
    token_b64: str
    unct: str


def parse_token_b64_or_uuid(token: str) -> Optional[uuid.UUID]:
    token = token.strip()
    try:
        return uuid.UUID(bytes=base64.urlsafe_b64decode(token))
    except ValueError:
        pass
    try:
        return uuid.UUID(hex=token)
    except ValueError:
        pass
    return None


@app.route("/api/tokens", methods=["GET", "POST"])
@auth.login_required
def tokens() -> ResponseReturnValue:
    tokens_raw = redis_client.hgetall(EXAUTH_AUTH_TOKENS_KEY)
    tokens_info = [
        TokenInfo(
            token=token,
            token_b64=base64.urlsafe_b64encode(uuid.UUID(token).bytes).decode(),
            unct=unct,
        )
        for token, unct in tokens_raw.items()
    ]

    if request.method == "GET":
        return render_template("tokens.html", tokens=tokens_info)

    unct_raw = request.form["customer"].strip()
    unct = parse_token_b64_or_uuid(unct_raw)
    if unct is None:
        return "UNCT is not UUID or base64 encoded UUID", 400

    new_token_raw = request.form["token"].strip()
    new_token = parse_token_b64_or_uuid(new_token_raw)
    if new_token is None:
        return "Token is not UUID or base64 encoded UUID", 400
    redis_client.hset(EXAUTH_AUTH_TOKENS_KEY, str(new_token), str(unct))
    return redirect("/api/tokens")


@app.route("/api/tokens/delete", methods=["POST"])
@auth.login_required
def token_delete() -> ResponseReturnValue:
    token_raw = request.form["token"].strip()
    token = parse_token_b64_or_uuid(token_raw)
    if token is None:
        return "Token is not UUID or base64 encoded UUID", 400
    redis_client.hdel(EXAUTH_AUTH_TOKENS_KEY, str(token))
    return redirect("/api/tokens")


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class StreamingTokenInfo:
    key: str
    unct: str
    service: str
    cluster: str
    version: str
    room: str
    env: str
    exp_at: datetime.datetime
    exp_in: datetime.timedelta
    token: str
    verified: bool


def get_streaming_token_info(
    key: str, value: str, now: datetime.datetime
) -> StreamingTokenInfo:
    _word1, _word2, unct, service, cluster, version, room, *rest = key.split("_")
    if rest:
        logger.warning("key contains unknown parts: %s", rest)

    kwargs: dict[str, Any] = {"key": SHARED_SECRET, "algorithms": ["HS256"]}
    verified = False
    try:
        payload = jwt.decode(value, **kwargs)
        verified = True
    except jwt.exceptions.InvalidTokenError:
        kwargs["options"] = {"verify_signature": False}
        payload = jwt.decode(value, **kwargs)

    env = payload.get("env", "")
    exp = datetime.datetime.fromtimestamp(payload.get("exp", 0), tz=datetime.UTC)
    return StreamingTokenInfo(
        key=key,
        unct=unct,
        service=service,
        cluster=cluster,
        version=version,
        room=room,
        env=env,
        exp_at=exp,
        exp_in=exp - now,
        token=value,
        verified=verified,
    )


@app.route("/api/streaming_tokens", methods=["GET"])
@auth.login_required
def streaming_tokens() -> ResponseReturnValue:
    keys = list(redis_client.scan_iter("EXAUTH_TOKEN_*"))
    values = redis_client.mget(keys)
    now = datetime.datetime.now(tz=datetime.UTC).replace(microsecond=0)

    tokens_info = [
        get_streaming_token_info(key, value, now)
        for key, value in zip(keys, values)
        if value is not None
    ]

    return render_template("streaming_tokens.html", tokens=tokens_info)


@app.route("/api/streaming_tokens/delete", methods=["POST"])
@auth.login_required
def delete_tokens() -> ResponseReturnValue:
    key = request.form["key"].strip()
    if key != "__ALL__":
        redis_client.delete(key)
    else:
        for key in redis_client.scan_iter("EXAUTH_TOKEN_*"):
            redis_client.delete(key)
    return redirect("/api/streaming_tokens")


@app.route("/", methods=["GET"])
def live() -> ResponseReturnValue:
    return b"Live!"

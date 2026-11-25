from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4
from sqlalchemy import select
from client.crypto import wrap_key, unwrap_key, encrypt_record
from server.models import User, Session, Vault, Record, AuditEvent
from server.security import token_hash
from shared.schemas import Envelope
from tests.conftest import seed, register, ACCOUNT_PASSWORD, MASTER


def test_database_no_seeded_plaintext_and_metadata(backend):
    app, client, _, path = backend
    a = seed(client)
    with app.state.sessions() as db:
        user = db.get(User, a["user"]["user_id"])
        assert user.password_algorithm == "PBKDF2-HMAC-SHA256"
        assert user.password_iterations >= 600000
        assert len(user.password_salt) == 16 and len(user.password_verifier) == 32
        assert user.password_salt != __import__("base64").b64decode(a["envelope"].salt)
        session = db.get(Session, token_hash(a["user"]["token"]))
        assert session and session.token_hash != a["user"]["token"]
        assert not {"title", "username", "password", "url", "notes"} & set(Record.__table__.columns.keys())
        assert list(db.scalars(select(AuditEvent)))
    raw = path.read_bytes()
    for secret in [*a["plain"].model_dump().values(), ACCOUNT_PASSWORD, MASTER, a["user"]["token"]]:
        assert secret.encode() not in raw
    assert a["key"] not in raw


def test_two_user_ownership_every_endpoint(backend):
    _, c, _, _ = backend
    a, b = seed(c), seed(c, "bob@example.test")
    h, v, r = b["headers"], a["vid"], a["rid"]
    updated = encrypt_record(a["key"], a["user"]["user_id"], v, r, 2, a["plain"])
    env = wrap_key(a["key"], MASTER, a["user"]["user_id"], v, 2)
    attempts = [
        ("GET", f"/vaults/{v}/envelope", None),
        ("PUT", f"/vaults/{v}/envelope", {"expected_revision": 1, "envelope": env.model_dump()}),
        ("GET", f"/vaults/{v}/records", None),
        ("POST", f"/vaults/{v}/records", a["record"].model_dump()),
        ("GET", f"/vaults/{v}/records/{r}", None),
        ("PUT", f"/vaults/{v}/records/{r}", {"expected_revision": 1, "record": updated.model_dump()}),
        ("DELETE", f"/vaults/{v}/records/{r}?expected_revision=1", None),
        ("GET", f"/vaults/{b['vid']}/records/{r}", None),
        ("PUT", f"/vaults/{b['vid']}/records/{r}", {"expected_revision": 1, "record": updated.model_dump()}),
        ("DELETE", f"/vaults/{b['vid']}/records/{r}?expected_revision=1", None),
    ]
    for method, path, data in attempts:
        response = c.request(method, path, headers=h, json=data)
        assert response.status_code == 404, (method, path, response.text)
        assert a["record"].ciphertext not in response.text
    visible = c.get("/vaults", headers=h).json()
    assert [x["id"] for x in visible] == [b["vid"]]
    # Caller-supplied ownership is forbidden, including at initialization.
    payload = {"id": str(uuid4()), "envelope": a["envelope"].model_dump(), "owner_id": a["user"]["user_id"]}
    assert c.post("/vaults", headers=h, json=payload).status_code == 422
    assert (
        c.post("/vaults", headers=h, json={"id": v, "envelope": a["envelope"].model_dump()}).status_code
        == 409
    )
    # Logout/password change act only on the bearer principal, never an arbitrary user ID.
    assert (
        c.post(
            "/auth/password",
            headers=h,
            json={
                "current_password": ACCOUNT_PASSWORD,
                "new_password": "Bob new password 47!",
                "user_id": a["user"]["user_id"],
            },
        ).status_code
        == 422
    )
    assert c.post("/auth/logout", headers=h).status_code == 204
    assert c.get("/vaults", headers=a["headers"]).status_code == 200


def test_unauthenticated_endpoints(backend):
    _, c, _, _ = backend
    a = seed(c)
    v, r = a["vid"], a["rid"]
    for method, path, body in [
        ("GET", "/vaults", None),
        ("POST", "/vaults", {"id": v, "envelope": a["envelope"].model_dump()}),
        ("GET", f"/vaults/{v}/envelope", None),
        ("PUT", f"/vaults/{v}/envelope", {"expected_revision": 1, "envelope": a["envelope"].model_dump()}),
        ("GET", f"/vaults/{v}/records", None),
        ("POST", f"/vaults/{v}/records", a["record"].model_dump()),
        ("GET", f"/vaults/{v}/records/{r}", None),
        ("PUT", f"/vaults/{v}/records/{r}", {"expected_revision": 1, "record": a["record"].model_dump()}),
        ("DELETE", f"/vaults/{v}/records/{r}?expected_revision=1", None),
        ("POST", "/auth/logout", None),
        ("POST", "/auth/password", {"current_password": ACCOUNT_PASSWORD, "new_password": ACCOUNT_PASSWORD}),
    ]:
        assert c.request(method, path, json=body).status_code == 401


def test_session_expiry_logout_and_hash_only(backend):
    _, c, now, _ = backend
    _, h = register(c)
    assert c.get("/vaults", headers=h).status_code == 200
    now[0] += 1801
    assert c.get("/vaults", headers=h).status_code == 401
    result = c.post("/auth/login", json={"email": "alice@example.test", "password": ACCOUNT_PASSWORD}).json()
    h = {"Authorization": "Bearer " + result["token"]}
    assert c.post("/auth/logout", headers=h).status_code == 204
    assert c.get("/vaults", headers=h).status_code == 401


def test_rate_limit_generic_errors(backend):
    app, c, _, _ = backend
    register(c)
    app.state.limiter.entries.clear()
    bad = {"email": "alice@example.test", "password": "wrong password value"}
    nonexistent = {**bad, "email": "nobody@example.test"}
    assert c.post("/auth/login", json=bad).json() == c.post("/auth/login", json=nonexistent).json()
    for _ in range(9):
        assert c.post("/auth/login", json=bad).status_code == 401
    response = c.post("/auth/login", json=bad)
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"


def test_stale_edits_delete_and_recreate(backend):
    _, c, _, _ = backend
    a = seed(c)
    v, r, h = a["vid"], a["rid"], a["headers"]
    update = encrypt_record(a["key"], a["user"]["user_id"], v, r, 2, a["plain"])
    path = f"/vaults/{v}/records/{r}"
    payload = {"expected_revision": 1, "record": update.model_dump()}
    assert c.put(path, headers=h, json=payload).status_code == 200
    assert c.put(path, headers=h, json=payload).status_code == 409
    assert c.delete(path + "?expected_revision=1", headers=h).status_code == 409
    assert c.delete(path + "?expected_revision=2", headers=h).status_code == 204
    assert c.get(path, headers=h).status_code == 404
    assert c.post(f"/vaults/{v}/records", headers=h, json=a["record"].model_dump()).status_code == 409


def test_atomic_concurrent_record_update(backend):
    _, c, _, _ = backend
    a = seed(c)
    path = f"/vaults/{a['vid']}/records/{a['rid']}"
    payloads = []
    for _ in range(2):
        new = encrypt_record(a["key"], a["user"]["user_id"], a["vid"], a["rid"], 2, a["plain"])
        payloads.append({"expected_revision": 1, "record": new.model_dump()})
    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(lambda p: c.put(path, headers=a["headers"], json=p), payloads))
    assert sorted(r.status_code for r in responses) == [200, 409]
    stored = c.get(path, headers=a["headers"]).json()
    winner = payloads[next(i for i, r in enumerate(responses) if r.status_code == 200)]
    assert stored["ciphertext"] == winner["record"]["ciphertext"]


def test_atomic_rewrap_concurrency(backend):
    app, c, _, _ = backend
    a = seed(c)
    uid, vid = a["user"]["user_id"], a["vid"]
    before = c.get(f"/vaults/{vid}/records", headers=a["headers"]).json()
    alternatives = [
        (MASTER + suffix, wrap_key(a["key"], MASTER + suffix, uid, vid, 2)) for suffix in (" one", " two")
    ]
    path = f"/vaults/{vid}/envelope"
    with ThreadPoolExecutor(2) as pool:
        responses = list(
            pool.map(
                lambda pair: c.put(
                    path,
                    headers=a["headers"],
                    json={"expected_revision": 1, "envelope": pair[1].model_dump()},
                ),
                alternatives,
            )
        )
    assert sorted(r.status_code for r in responses) == [200, 409]
    winner = alternatives[next(i for i, r in enumerate(responses) if r.status_code == 200)]
    current = Envelope(**c.get(path, headers=a["headers"]).json()["envelope"])
    assert current == winner[1]
    assert unwrap_key(current, winner[0], uid, vid) == a["key"]
    assert before == c.get(f"/vaults/{vid}/records", headers=a["headers"]).json()
    with app.state.sessions() as db:
        assert db.get(Vault, vid).envelope_revision == 2


def test_account_password_change_separate_from_vault(backend):
    _, c, _, _ = backend
    a = seed(c)
    second = c.post("/auth/login", json={"email": "alice@example.test", "password": ACCOUNT_PASSWORD}).json()
    new = "Account changed password 472!"
    assert (
        c.post(
            "/auth/password",
            headers=a["headers"],
            json={"current_password": ACCOUNT_PASSWORD, "new_password": new},
        ).status_code
        == 204
    )
    for token in (a["user"]["token"], second["token"]):
        assert c.get("/vaults", headers={"Authorization": "Bearer " + token}).status_code == 401
    assert (
        c.post("/auth/login", json={"email": "alice@example.test", "password": ACCOUNT_PASSWORD}).status_code
        == 401
    )
    result = c.post("/auth/login", json={"email": "alice@example.test", "password": new}).json()
    h = {"Authorization": "Bearer " + result["token"]}
    env = Envelope(**c.get(f"/vaults/{a['vid']}/envelope", headers=h).json()["envelope"])
    assert env == a["envelope"]
    assert unwrap_key(env, MASTER, a["user"]["user_id"], a["vid"]) == a["key"]


def test_malformed_size_and_no_secret_error_echo(backend):
    _, c, _, _ = backend
    distinctive = "VERY-DISTINCTIVE-SHOULD-NOT-ECHO"
    result = c.post("/auth/login", json={"email": "bad", "password": distinctive, "unexpected": distinctive})
    assert result.status_code == 422 and distinctive not in result.text
    assert c.post("/auth/login", content="{broken").status_code == 422
    assert c.post("/auth/login", content="x" * 70000).status_code == 413
    chunks = iter([b"x" * 40000, b"x" * 40000])
    assert c.post("/auth/login", content=chunks).status_code == 413
    a = seed(c)
    for change in ({"nonce": "bad"}, {"key_version": 99}, {"revision": True}, {"ciphertext": "!!!"}):
        payload = {**a["record"].model_dump(), **change}
        assert c.post(f"/vaults/{a['vid']}/records", headers=a["headers"], json=payload).status_code == 422
    assert c.get(f"/vaults/{a['vid']}/records?limit=101", headers=a["headers"]).status_code == 422
    assert c.get("/vaults/not-a-uuid/envelope", headers=a["headers"]).status_code == 422


def test_bounded_rate_limiter():
    from server.security import RateLimiter

    now = [0]
    limiter = RateLimiter(clock=lambda: now[0], capacity=2)
    assert limiter.allow("a", 1)
    assert not limiter.allow("a", 1)
    assert limiter.allow("b", 1)
    assert not limiter.allow("c", 1)
    now[0] = 61
    assert limiter.allow("c", 1)


def test_password_change_cannot_affect_other_user(backend):
    _, c, _, _ = backend
    a, a_headers = register(c)
    b, b_headers = register(c, "bob@example.test")
    assert (
        c.post(
            "/auth/password",
            headers=b_headers,
            json={
                "current_password": "Incorrect password 42!",
                "new_password": "Bob new account password 73!",
            },
        ).status_code
        == 401
    )
    assert c.get("/vaults", headers=b_headers).status_code == 200
    assert (
        c.post(
            "/auth/password",
            headers=b_headers,
            json={"current_password": ACCOUNT_PASSWORD, "new_password": "Bob new account password 73!"},
        ).status_code
        == 204
    )
    assert c.get("/vaults", headers=b_headers).status_code == 401
    assert c.get("/vaults", headers=a_headers).status_code == 200

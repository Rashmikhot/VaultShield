from tests.conftest import register


def test_attack_simulations_are_authenticated_and_persisted(backend):
    _, client, _, _ = backend
    user, headers = register(client)
    denied = client.post("/security/simulations", json={"kind": "mitm"})
    assert denied.status_code == 401

    for kind, expected in [
        ("mitm", "IMPOSTOR CERTIFICATE REJECTED"),
        ("replay", "REPLAY REJECTED"),
        ("bruteforce", "BRUTE-FORCE ATTEMPTS THROTTLED"),
        ("tamper", "TAMPERED CIPHERTEXT REJECTED"),
    ]:
        response = client.post("/security/simulations", headers=headers, json={"kind": kind})
        assert response.status_code == 200
        data = response.json()
        assert data["outcome"] == expected
        assert data["server_recorded"] is True
        assert data["simulation_id"]
        assert data["execution_trace"]
        assert data["execution_evidence"]
        assert data["execution_logs"]
        assert data["before_after"]["before"]
        assert data["before_after"]["after"]
        assert data["target_scope"].startswith("Isolated localhost")

    history = client.get("/security/simulations", headers=headers)
    assert history.status_code == 200
    assert len(history.json()) == 4
    assert all(item["event"].startswith("simulation.") for item in history.json())


def test_unknown_simulation_is_rejected(backend):
    _, client, _, _ = backend
    _, headers = register(client)
    response = client.post("/security/simulations", headers=headers, json={"kind": "unknown"})
    assert response.status_code == 422

from datetime import datetime, timezone

from switchmap_py.storage.idlesince_store import IdleSinceStore, PortIdleState


def test_idle_transition(tmp_path):
    store = IdleSinceStore(tmp_path)
    ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
    state = PortIdleState(port="Gi1/0/1", idle_since=None, last_active=None)

    updated = store.update_port(state, port=state.port, is_active=False, observed_at=ts)
    assert updated.idle_since == ts
    assert updated.last_active is None

    updated_active = store.update_port(updated, port=state.port, is_active=True, observed_at=ts)
    assert updated_active.idle_since is None
    assert updated_active.last_active == ts

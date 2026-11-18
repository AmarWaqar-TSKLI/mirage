"""Regression: concurrent ingest + dashboard reads must not corrupt attacker state.

The controller shares one SQLite connection across threads. If reads run on it
while another thread is mid-write, a read inside Engine.process can come back
empty, the engine treats the attacker as brand new, and overwrites its row
(event_count, max_stage and techniques regress). This drives many writers and
readers at once and checks the attacker row still matches the event table.
"""

import threading
from pathlib import Path

from mirage_common import Event, Registry

try:
    from app.engine import Engine
    from app.store import Store
except ImportError:
    from controller.app.engine import Engine
    from controller.app.store import Store

HONEYTOKENS = Path(__file__).parents[2] / "config" / "honeytokens.json"
IP = "10.66.0.50"
WRITERS, PER_WRITER, READERS = 8, 40, 3


def test_concurrent_ingest_and_reads_keep_attacker_consistent(tmp_path):
    store = Store(tmp_path / "mirage.db")
    engine = Engine(store, Registry.load(HONEYTOKENS))
    errors: list[Exception] = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                store.attackers()
                store.recent("events", 50)
                store.recent("alerts", 50)
                store.get_attacker(IP)
            except Exception as e:  # noqa: BLE001 - any failure is the bug
                errors.append(e)

    def writer(k: int):
        for i in range(PER_WRITER):
            try:
                engine.process(Event(source="admin-panel", event_type="http_request",
                                     src_ip=IP, asset=f"/probe-{k}-{i}"))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

    # Reach stage 3 early so a regression of max_stage is detectable.
    engine.process(Event(source="ssh", event_type="login_attempt", src_ip=IP,
                         honeytoken_id="ht-ssh-password", details={"success": True}))

    readers = [threading.Thread(target=reader) for _ in range(READERS)]
    writers = [threading.Thread(target=writer, args=(k,)) for k in range(WRITERS)]
    for t in readers + writers:
        t.start()
    for t in writers:
        t.join()
    stop.set()
    for t in readers:
        t.join()

    assert not errors, f"{len(errors)} errors, first: {errors[0]!r}"
    a = store.get_attacker(IP)
    total = 1 + WRITERS * PER_WRITER
    assert a["event_count"] == total
    assert a["max_stage"] == 3
    assert len(store.recent("events", 10_000, IP)) == total

"""verify_sessions.py - Regressionstest fuer die offen gehaltene P2P-Sitzung.

Prueft ohne Netz, ohne Home Assistant und ohne Tuerstation die Logik, die seit
v0.10.0 daran haengt, dass das Geraet nur EINE Sitzung bedient und danach
Erholung braucht (P2P_PROTOCOL.md Abschnitt 10.3):

  * der Slot: Uebernahme, Ablauf, Verdraengung, Abstand pro Geraet
  * genau EIN Schliessen je Sitzung -- weder doppelt noch gar nicht
  * der Pruef-Frame vor jedem Befehl (Wiederholung bei Paketverlust)
  * das Oeffnen selbst: dass ein zweites Oeffnen ein NEUER Befehl auf einem
    neuen Byte-Offset ist und nicht als Wiederholung durchgeht
  * die Geheimnis-Auffrischung, die das Oeffnen nur kurz aufhalten darf

Genau die Faelle, die sich an der echten Station nur schwer provozieren lassen
und beim letzten Umbau reihenweise danebengingen.

    python tools/verify_sessions.py     # Exit 0 = alle Pruefungen bestanden
"""
from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import sys
import threading
import time
import types

ROOT = pathlib.Path(__file__).resolve().parent.parent
COMPONENT = ROOT / "custom_components" / "balter_evo"


def _load(module: str):
    """Import one integration module without pulling in Home Assistant."""
    for name in ("homeassistant", "homeassistant.core"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["homeassistant.core"].HomeAssistant = object
    sys.modules["homeassistant"].core = sys.modules["homeassistant.core"]

    if "paho.mqtt.client" not in sys.modules:
        paho = types.ModuleType("paho")
        mqtt = types.ModuleType("paho.mqtt")
        client = types.ModuleType("paho.mqtt.client")
        client.Client = object
        client.MQTTv31 = 3
        client.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)
        paho.mqtt = mqtt
        mqtt.client = client
        sys.modules.update(
            {"paho": paho, "paho.mqtt": mqtt, "paho.mqtt.client": client}
        )

    pkg_name = "balter_evo_offline"
    if pkg_name not in sys.modules:
        pkg = types.ModuleType(pkg_name)
        pkg.__path__ = [str(COMPONENT)]
        sys.modules[pkg_name] = pkg

    full = f"{pkg_name}.{module}"
    if full in sys.modules:
        return sys.modules[full]
    spec = importlib.util.spec_from_file_location(full, COMPONENT / f"{module}.py")
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[full] = loaded
    spec.loader.exec_module(loaded)
    return loaded


p2p = _load("p2p")
api = _load("api")

p2p.P2P_MIN_GAP = 1.0
IDLE = 0.4
SIG = ("pw", "cid", "oem", b"k" * 32)

_checks = 0


def ok(message: str) -> None:
    """Report one passed check."""
    global _checks
    _checks += 1
    print(f"  ok: {message}")


# --------------------------------------------------------------- Doppel

class FakeTransport:
    """Zaehlt Pflegeschritte und Schliessungen, sonst passiv."""

    def __init__(self, duid: str = "dev1") -> None:
        """Start a transport double for ``duid``."""
        self._duid = duid
        self.ticks = 0
        self.closed = False
        self.closes = 0
        self.device_ready = threading.Event()
        self.device_ready.set()

    @property
    def duid(self) -> str:
        """Return the device this double belongs to."""
        return self._duid

    def maintain(self) -> None:
        """Count one keepalive tick."""
        self.ticks += 1

    def close(self) -> None:
        """Count one close."""
        self.closed = True
        self.closes += 1

    def set_media_sink(self, callback) -> None:
        """Accept and ignore a media sink."""


class FakeStation(FakeTransport):
    """Quittiert wie die Station jeden empfangenen Byte-Offset."""

    def __init__(self, duid: str = "dev1") -> None:
        """Start a station double that acks everything immediately."""
        super().__init__(duid)
        self.chan = types.SimpleNamespace(peer_ack=0, last_pos=0, last_frame=b"")
        self.channels = {p2p.CH0: self.chan}
        self.logged_in = threading.Event()
        self.logged_in.set()
        self.sent_pos = 1
        self.commands: list[tuple[int, int | None, int]] = []
        self.setups = 0

    def send_ctrl(self, outer_msg, ftype, payload=b"", conv=None, **fields):
        """Record one control frame and acknowledge it."""
        start = self.sent_pos
        self.sent_pos += 128
        self.commands.append((outer_msg, fields.get("msg13"), start))
        self.chan.last_pos = start
        self.chan.peer_ack = self.sent_pos
        return start, self.sent_pos

    def send_session_setup(self) -> None:
        """Count one session-setup burst."""
        self.setups += 1

    def resend_last(self, conv) -> None:
        """Accept and ignore a retransmit request."""

    def connect(self) -> bool:
        """Pretend the handshake succeeded."""
        return True

    def wait_until(self, event, deadline) -> bool:
        """Report the event state without waiting."""
        return event.is_set()

    def wait(self, event, timeout) -> bool:
        """Report the event state without waiting."""
        return event.is_set()

    def handshake_states(self) -> str:
        """Return a handshake summary for error logs."""
        return "CH1000000=LOGGED_IN"

    def opendoors(self) -> list[tuple[int, int | None, int]]:
        """Return every unlock frame this station received."""
        return [cmd for cmd in self.commands if cmd[1] == 4]


# ------------------------------------------------------------ Slot-Logik

def check_slot() -> None:
    """Uebernahme, Ablauf, Verdraengung und Erholungsabstand."""
    print("Slot und offen gehaltene Sitzung")

    first = FakeTransport()
    with p2p._P2PSlot("A", "dev1", SIG, reuse=True, warm_idle=IDLE) as slot:
        assert slot.transport is None
        slot.transport = first
        slot.keep_warm = True
    assert not first.closed and "dev1" in p2p._WARM

    time.sleep(0.1)
    assert first.ticks > 0, "Keepalive haelt die Sitzung nicht am Leben"

    started = time.monotonic()
    with p2p._P2PSlot("B", "dev1", SIG, reuse=True, warm_idle=IDLE) as slot:
        assert slot.transport is first, "warme Sitzung wurde nicht uebernommen"
        waited = time.monotonic() - started
        assert waited < 0.5, f"Wiederverwendung wartete {waited:.2f}s"
        slot.keep_warm = True
    ok("Sitzung wird gehalten und ohne Abstand wiederverwendet")

    time.sleep(0.8)
    assert first.closed and "dev1" not in p2p._WARM
    ok("abgelaufene Sitzung wird geschlossen")

    started = time.monotonic()
    with p2p._P2PSlot("C", "dev2", SIG, warm_idle=IDLE):
        pass
    assert time.monotonic() - started < 0.3, "Abstand von dev1 bremste dev2 aus"
    ok("Erholungsabstand wird pro Geraet gefuehrt")

    p2p._P2P_LAST_END["dev1"] = time.monotonic()
    started = time.monotonic()
    with p2p._P2PSlot("D", "dev1", SIG, reuse=True, warm_idle=IDLE) as slot:
        assert slot.transport is None
    assert time.monotonic() - started >= 0.9, "Erholungsabstand nicht eingehalten"
    ok("nach echtem Sitzungsende bleibt der Abstand bestehen")

    rotated = FakeTransport("dev1")
    with p2p._P2PSlot("E", "dev1", SIG, reuse=True, warm_idle=IDLE) as slot:
        slot.transport = rotated
        slot.keep_warm = True
    with p2p._P2PSlot(
        "F", "dev1", ("neu", "cid", "oem", b"k" * 32), reuse=True, warm_idle=IDLE
    ) as slot:
        assert slot.transport is None, "Sitzung mit alten Geheimnissen uebernommen"
    assert rotated.closed
    ok("rotierte Geheimnisse verwerfen die alte Sitzung")

    other = FakeTransport("dev1")
    with p2p._P2PSlot("G", "dev1", SIG, reuse=True, warm_idle=IDLE) as slot:
        slot.transport = other
        slot.keep_warm = True
    with p2p._P2PSlot("H", "dev2", SIG, reuse=True, warm_idle=IDLE) as slot:
        assert slot.transport is None
    assert other.closed, "Sitzung eines anderen Geraets nicht freigegeben"
    ok("warme Sitzung weicht einem anderen Geraet")


def check_handover() -> None:
    """Uebergabe einer Kamerasitzung an ein wartendes Tueroeffnen."""
    print("Uebergabe Kamera -> Tueroeffnen")

    handed = FakeTransport("dev1")
    p2p._UNLOCK_WANTED.set()
    with p2p._P2PSlot("Snapshot", "dev1", SIG, warm_idle=IDLE) as slot:
        slot.transport = handed
        p2p._release_or_hand_over(slot, handed, "snapshot")
        assert slot.keep_warm and slot.transport is handed
    assert not handed.closed and "dev1" in p2p._WARM
    p2p._UNLOCK_WANTED.clear()
    with p2p._P2PSlot("Door unlock", "dev1", SIG, reuse=True, warm_idle=IDLE) as slot:
        assert slot.transport is handed, "uebergebene Sitzung kam nicht an"
        slot.drop_transport()
    assert handed.closed
    ok("laufende Kamerasitzung wird ans Oeffnen weitergereicht")

    lone = FakeTransport("dev3")
    with p2p._P2PSlot("Snapshot", "dev3", SIG, warm_idle=IDLE) as slot:
        slot.transport = lone
        p2p._release_or_hand_over(slot, lone, "snapshot")
    assert lone.closed and "dev3" not in p2p._WARM
    ok("ohne wartendes Oeffnen wird normal geschlossen")


def check_disabled() -> None:
    """warm_idle = 0 stellt das Verhalten von vor v0.10.0 her."""
    print("Haltedauer 0 (Offenhalten abgeschaltet)")

    closed = FakeTransport("dev4")
    with p2p._P2PSlot("Door unlock", "dev4", SIG, reuse=True, warm_idle=0) as slot:
        slot.transport = closed
        slot.keep_warm = True
    assert closed.closed and "dev4" not in p2p._WARM
    ok("Sitzung wird trotz keep_warm geschlossen")

    no_handover = FakeTransport("dev5")
    p2p._UNLOCK_WANTED.set()
    with p2p._P2PSlot("Snapshot", "dev5", SIG, warm_idle=0) as slot:
        slot.transport = no_handover
        p2p._release_or_hand_over(slot, no_handover, "snapshot")
    p2p._UNLOCK_WANTED.clear()
    assert no_handover.closed and "dev5" not in p2p._WARM
    ok("auch die Sitzungsuebergabe unterbleibt")

    settled = FakeTransport("dev6")
    started = time.monotonic()
    with p2p._P2PSlot("Door unlock", "dev6", SIG, reuse=True, warm_idle=0) as slot:
        slot.transport = settled
        slot.keep_warm = True
        slot.settle = 0.3
    took = time.monotonic() - started
    assert settled.closed and took >= 0.29, f"Nachlaufzeit uebersprungen ({took:.2f}s)"
    ok("die Nachlaufzeit vor dem Close wird abgewartet")


def check_single_close() -> None:
    """Jede Sitzung wird genau einmal geschlossen -- auf jedem Abbauweg."""
    print("Genau ein Schliessen je Sitzung")

    for label, how in (("Ablauf", None), ("Verdraengung", "other"), ("Entladen", "release")):
        transport = FakeTransport("dev9")
        with p2p._P2PSlot("Door unlock", "dev9", SIG, reuse=True, warm_idle=0.3) as slot:
            slot.transport = transport
            slot.keep_warm = True
        if how == "other":
            with p2p._P2PSlot("Snapshot", "devX", SIG, warm_idle=IDLE):
                pass
        elif how == "release":
            p2p.release_all_sessions()
        else:
            time.sleep(0.6)
        assert transport.closes == 1, f"{label}: {transport.closes}x geschlossen"
        p2p._P2P_LAST_END.pop("dev9", None)
        p2p._P2P_LAST_END.pop("devX", None)
    ok("Ablauf, Verdraengung und Entladen schliessen je genau einmal")


def check_stuck_keepalive() -> None:
    """Ein haengender Keepalive-Thread haelt die Sitzung -- die Station ist belegt."""
    print("Haengender Keepalive-Thread")

    class Stuck(FakeTransport):
        def maintain(self) -> None:
            time.sleep(2.0)

    stuck = Stuck("dev10")
    with p2p._P2PSlot("Door unlock", "dev10", SIG, reuse=True, warm_idle=IDLE) as slot:
        slot.transport = stuck
        slot.keep_warm = True
    time.sleep(0.05)
    p2p._P2P_LAST_END.pop("dev10", None)
    started = time.monotonic()
    with p2p._P2PSlot("Door unlock", "dev10", SIG, reuse=True, warm_idle=IDLE) as slot:
        assert slot.transport is None, "haengende Sitzung wurde uebernommen"
    waited = time.monotonic() - started
    assert waited >= 0.9, f"Abstand uebersprungen ({waited:.2f}s) -- zweite Sitzung daneben"
    ok("erzwingt den Erholungsabstand statt einer zweiten Sitzung")


def check_probe() -> None:
    """Der Pruef-Frame vor jedem Befehl vertraegt ein verlorenes Paket."""
    print("Pruef-Frame vor dem Befehl")

    class Flaky:
        """Quittiert erst nach der Wiederholung."""

        def __init__(self) -> None:
            self.chan = types.SimpleNamespace(peer_ack=0)
            self.channels = {p2p.CH0: self.chan}
            self.end = 100
            self.resends = 0
            self.answers = True

        @property
        def duid(self) -> str:
            return "dev8"

        def send_ctrl(self, *args, **kwargs):
            return (0, self.end)

        def maintain(self) -> None:
            pass

        def resend_last(self, conv) -> None:
            self.resends += 1
            if self.answers:
                self.chan.peer_ack = self.end

    flaky = Flaky()
    assert p2p._warm_session_alive(flaky, time.monotonic() + 5)
    assert flaky.resends == 1, f"nicht wiederholt (resends={flaky.resends})"
    ok("ein verlorenes Paket verwirft die Sitzung nicht mehr")

    dead = Flaky()
    dead.answers = False
    assert not p2p._warm_session_alive(dead, time.monotonic() + 5)
    ok("eine wirklich tote Sitzung wird trotzdem erkannt")


# ------------------------------------------------------------- Tueroeffnen

def _unlock(duid: str, station: FakeStation, warm_idle: float = 5.0):
    """Ein Oeffnen ueber den echten Slot- und Oeffnen-Pfad."""
    original = p2p._P2PTransport
    p2p._P2PTransport = lambda *args, **kwargs: station
    try:
        with p2p._P2PSlot(
            "Door unlock", duid, SIG, reuse=True, warm_idle=warm_idle
        ) as slot:
            return p2p._open_door(
                slot, duid, "pw", "", client_id="cid", door=1, locknumber=1,
                key=b"k" * 32,
            ), slot.transport
    finally:
        p2p._P2PTransport = original


def check_open_door() -> None:
    """Das Oeffnen selbst, einmal frisch und einmal auf der offenen Sitzung."""
    print("Tueroeffnen")
    p2p.release_all_sessions()
    p2p._P2P_LAST_END.clear()

    station = FakeStation("dev11")
    result, _ = _unlock("dev11", station)
    assert result.acked and result.ready and result.sent, result
    assert len(station.opendoors()) == 1, station.commands
    assert station.setups == 1, "Setup-Frames fehlten"
    assert station.closes == 0, "Sitzung wurde geschlossen statt gehalten"
    ok("erstes Oeffnen quittiert, die Sitzung bleibt stehen")

    result, transport = _unlock("dev11", FakeStation("unbenutzt"))
    assert result.acked, result
    assert transport is station, "die offene Sitzung wurde nicht wiederverwendet"
    assert station.setups == 1, "Setup-Frames auf der laufenden Sitzung wiederholt"

    unlocks = station.opendoors()
    assert len(unlocks) == 2, station.commands
    first, second = unlocks[0][2], unlocks[1][2]
    assert second > first, (
        f"zweites OPENDOOR auf demselben Byte-Offset ({second}) -- die Station "
        "saehe eine Wiederholung und wuerde NICHT erneut oeffnen"
    )
    probes = [cmd for cmd in station.commands if cmd[1] == 2]
    assert probes and probes[-1][2] < second, "vor dem Befehl wurde nicht geprueft"
    ok(f"zweites Oeffnen ist ein NEUER Befehl (Offset {first} -> {second})")

    p2p.release_all_sessions()
    p2p._P2P_LAST_END.clear()

    dead = FakeStation("dev12")
    dead.send_ctrl = lambda *args, **kwargs: (1, 999999)   # nie quittiert
    fresh = FakeStation("dev12")
    with p2p._P2PSlot("Door unlock", "dev12", SIG, reuse=True, warm_idle=5.0) as slot:
        slot.transport = dead
        slot.keep_warm = True
    result, _ = _unlock("dev12", fresh)
    assert dead.closes >= 1, "tote Sitzung wurde nicht geschlossen"
    assert result.acked, "nach dem Verwerfen wurde nicht neu aufgebaut"
    assert fresh.opendoors() and fresh.setups == 1
    ok("tote Sitzung wird verworfen und sauber ersetzt")

    p2p.release_all_sessions()


# ------------------------------------------------------------- Geheimnisse

def _client() -> api.BalterCloudClient:
    client = api.BalterCloudClient(object(), "a@b.c", "pw", client_id="0123456789abcdef")
    client._cred_cache["dev"] = (
        time.time() - 3600,
        {"dynamic_password": "alt", "data_encode_key": "k", "out_auth_code": "o"},
    )
    return client


async def _check_credentials() -> None:
    print("Geheimnisse fuers Tueroeffnen")

    client = _client()

    async def quick():
        await asyncio.sleep(0.05)
        client._cred_cache["dev"] = (
            time.time(),
            {"dynamic_password": "neu", "data_encode_key": "k", "out_auth_code": "o"},
        )
        return []

    client.get_device_list = quick
    creds = await client.get_device_credentials("dev", allow_stale=True)
    assert creds["dynamic_password"] == "neu", creds
    ok("eine schnelle Cloud liefert dem Oeffnen die frischen Werte")

    client = _client()
    hanging = asyncio.Event()

    async def slow():
        await hanging.wait()
        return []

    client.get_device_list = slow
    started = time.monotonic()
    creds = await client.get_device_credentials("dev", allow_stale=True)
    took = time.monotonic() - started
    assert creds["dynamic_password"] == "alt", creds
    assert api.CREDENTIAL_REFRESH_WAIT - 0.1 <= took < api.CREDENTIAL_REFRESH_WAIT + 0.5, took
    assert not client._refresh_task.done(), "der geteilte Task wurde abgebrochen"
    hanging.set()
    await client._refresh_task
    ok(f"eine haengende Cloud haelt das Oeffnen nur {took:.1f}s auf")

    client = _client()

    async def broken():
        raise RuntimeError("unerwartet")

    client.get_device_list = broken
    creds = await client.get_device_credentials("dev", allow_stale=True)
    assert creds["dynamic_password"] == "alt", creds
    ok("ein Fehler der Auffrischung laesst das Oeffnen nicht scheitern")

    client = _client()
    never = asyncio.Event()

    async def waiting():
        await never.wait()
        return []

    client.get_device_list = waiting
    client._refresh_credentials_soon()
    task = client._refresh_task
    await asyncio.sleep(0)
    await client.async_close()
    assert (task.cancelled() or task.done()) and client._refresh_task is None
    ok("das Entladen beendet die Hintergrundauffrischung")


# ------------------------------------------------------- Schnappschuss-Fenster

def _nal(header: int, size: int) -> bytes:
    """Eine H.264-NAL-Einheit: Startcode, Kopfbyte und Fuellung.

    ``header`` ist das vollstaendige NAL-Kopfbyte, wie es die Station sendet
    (0x67 SPS, 0x68 PPS, 0x65 IDR, 0x41 P-Bild) -- nicht nur die Typnummer.
    """
    return bytes([0, 0, 0, 1, header]) + bytes([0x42]) * size


def _media_frame(plain: bytes, key: bytes) -> bytes:
    """Ein Medien-Frame, so wie ihn die Station schickt (Kopf verschluesselt)."""
    body = p2p.cbc_encrypt(plain[:64], key) + plain[64:]
    return p2p.build_app_frame(0, body, 0, bytes([1, 2, 3]))


def check_snapshot_window() -> None:
    """Der Schnappschuss endet mit dem Bild, nicht erst mit dem Zeitfenster."""
    print("Schnappschuss endet, sobald das Bild da ist")
    key = b"k" * 32
    p2p._MediaCollector.CHECK_INTERVAL = 0.0
    try:
        # Parametersatz plus ein P-Bild: reichlich Material, aber kein Keyframe.
        no_key = _media_frame(
            _nal(0x67, 40) + _nal(0x68, 30) + _nal(0x41, 5000), key
        )
        key_frame = _media_frame(_nal(0x65, 5000), key)

        assembler = p2p._StreamAssembler()
        collector = p2p._MediaCollector(assembler, key)
        assembler.add(1, no_key)
        assert not collector.has_still()
        ok("ohne Keyframe gilt das Bild als unfertig")

        assembler.add(1 + len(no_key), key_frame)
        assert collector.has_still()
        ok("mit Keyframe ist der Schnappschuss sofort fertig")

        whole = no_key + key_frame
        assert collector.frames() == [f for _, f in p2p.extract_app_frames(whole)]
        assert p2p.h264_is_decodable(p2p._decode_media(collector.frames(), (key,)))
        ok("der Sammler liefert dieselben Frames wie die Auswertung am Stueck")
    finally:
        p2p._MediaCollector.CHECK_INTERVAL = 0.25


# --------------------------------------------------- Freigabe der App-Sitzung

def _logged_in_transport(key: bytes):
    """Ein Transport im Zustand nach dem LOGIN, ohne Socket und ohne Netz."""
    transport = p2p._P2PTransport("dev1", "pw", "0123456789abcdef", key)
    chan = transport.channels[p2p.CH0]
    chan.myid = 0x11
    chan.sess = bytes([1, 2, 3])
    chan.state = "LOGGED_IN"
    return transport, chan


def _from_device(chan, payload: bytes) -> bytes:
    """Ein Datenpaket, wie es die Station auf CH0 schickt."""
    return p2p.build_transport_hdr(
        p2p.CH0, chan.myid, chan.rcv, 1, payload, win=p2p.WIN_DATA
    )


def check_ready_detection() -> None:
    """Die Station gibt die Sitzung frei -- das darf nicht uebersehen werden."""
    print("Freigabe der App-Sitzung")
    key = b"k" * 32

    transport, chan = _logged_in_transport(key)
    ready = p2p.build_app_frame(
        7, p2p.ctrl_frame(0xFE, 0, bytes([0, 1]), key=key, msg13=2), 0, chan.sess
    )
    # Die Freigabe steckt HINTER einem Medien-Frame im selben Paket -- genau so
    # kam sie in der Sitzung an, in der ein Tueroeffnen anschliessend ins
    # Zeitlimit lief, obwohl das Geraet laengst Video sendete.
    transport._handle_packet(
        _from_device(chan, _media_frame(_nal(0x65, 1200), key) + ready), ("1.2.3.4", 5)
    )
    assert transport.device_ready.is_set()
    ok("wird auch hinter einem Medien-Frame im selben Paket gefunden")

    transport, chan = _logged_in_transport(key)
    for _ in range(4):
        transport._handle_packet(_from_device(chan, bytes(1400)), ("1.2.3.4", 5))
        chan.rcv += 1400
    assert transport.device_ready.is_set()
    ok("der laufende Videostrom allein beweist sie ebenfalls")

    transport, chan = _logged_in_transport(key)
    transport._handle_packet(_from_device(chan, bytes(1400)), ("1.2.3.4", 5))
    assert not transport.device_ready.is_set()
    ok("ein einzelnes Paket reicht als Beweis dagegen nicht")


# ------------------------------------------------------- Cloud-Signalisierung

class FakeMqtt:
    """Ein paho-Client, der nur ueber seinen Verbindungszustand Auskunft gibt."""

    def __init__(self) -> None:
        """Start out connected."""
        self.connected = True

    def is_connected(self) -> bool:
        """Report the current connection state."""
        return self.connected

    def loop_stop(self) -> None:
        """Accept the request to stop the network loop."""

    def disconnect(self) -> None:
        """Note the disconnect."""
        self.connected = False

    def publish(self, *args, **kwargs) -> None:
        """Swallow published messages."""


def check_signalling_reuse() -> None:
    """Die Signalisierung bleibt offen -- aber ihr wird nicht blind vertraut."""
    print("Cloud-Signalisierung")
    p2p._SIGNALLING.clear()
    connects: list[str] = []
    original = p2p.CloudP2PSession.connect

    def fake_connect(self) -> None:
        connects.append(self.duid)
        self.cli = FakeMqtt()
        self.registered.set()

    p2p.CloudP2PSession.connect = fake_connect
    try:
        first, reused = p2p.CloudP2PSession.acquire("0123456789abcdef", "dev1")
        assert not reused and connects == ["dev1"]
        flag, requ = first.session_flag, first.requ_id

        second, reused = p2p.CloudP2PSession.acquire("0123456789abcdef", "dev1")
        assert second is first and reused and connects == ["dev1"]
        assert second.session_flag != flag and second.requ_id != requ
        ok("das zweite Kommando spart sich Broker, TLS und Anmeldung")

        second.close()
        assert second.usable()
        ok("das Ende eines Kommandos trennt die Verbindung nicht")

        second.got_addr.clear()
        # Verspaetete Antwort auf die ERSTE Anfrage -- sie traegt deren Nummer.
        second._read_addresses(
            {"utd-pub-ip": "1.2.3.4", "utd-pub-udpport": 1, "resp-session-id": requ}
        )
        assert second.relay is None and not second.got_addr.is_set()
        second._read_addresses(
            {"utd-pub-ip": "5.6.7.8", "utd-pub-udpport": 2,
             "resp-session-id": second.requ_id}
        )
        assert second.relay == ("5.6.7.8", 2)
        ok("die verspaetete Antwort des vorigen Kommandos wird verworfen")

        first.cli.connected = False
        third, reused = p2p.CloudP2PSession.acquire("0123456789abcdef", "dev1")
        assert third is not first and not reused and connects == ["dev1", "dev1"]
        assert first.cli is None
        ok("eine abgerissene Verbindung wird sauber ersetzt")

        p2p.release_all_sessions()
        assert third.cli is None and not p2p._SIGNALLING
        ok("das Entladen der Integration trennt auch die Signalisierung")
    finally:
        p2p.CloudP2PSession.connect = original
        p2p._SIGNALLING.clear()


def main() -> int:
    """Run every check; return 0 when they all passed."""
    check_slot()
    check_handover()
    check_disabled()
    check_single_close()
    check_stuck_keepalive()
    check_probe()
    check_open_door()
    check_snapshot_window()
    check_ready_detection()
    check_signalling_reuse()
    asyncio.run(_check_credentials())
    print(f"\n{_checks} Pruefungen bestanden")
    return 0


if __name__ == "__main__":
    sys.exit(main())

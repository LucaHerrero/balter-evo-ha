"""Quvii Cloud HTTP API client for Balter EVO door stations."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import re
import secrets
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from xml.sax.saxutils import escape as _xml_escape

import aiohttp
from yarl import URL

from .const import (
    APP_ID,
    BASE_PATH,
    CLIENT_TYPE,
    CLIENT_VERSION,
    CREDENTIAL_MAX_AGE,
    CREDENTIAL_REFRESH_WAIT,
    CREDENTIAL_STALE_AGE,
    DISCOVERY_HOST,
    DISCOVERY_PATH,
    HOST,
    IP_REGION_ID,
    OEM_ID,
    REQUEST_TIMEOUT,
    USER_AGENT,
)

_LOGGER = logging.getLogger(__name__)


def _sha256(val: str) -> str:
    """Compute the hexadecimal SHA-256 hash of a string."""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


# Die Cloud schreibt Schloss-Codes je nach Firmware unterschiedlich:
# "lock_chn1 1" (EVO 2, live beobachtet) oder "door1-lock1". Beide meinen
# Kanal (= Tuerstation) und Schlossnummer, beide 1-basiert -- genau die
# Indizes, die der OPENDOOR-Frame traegt.
_LOCK_CODE_RES = (
    re.compile(r"^lock_chn(?P<door>\d+)[ _-]+(?P<lock>\d+)$", re.IGNORECASE),
    re.compile(r"^door(?P<door>\d+)-lock(?P<lock>\d+)$", re.IGNORECASE),
)


def _parse_lock_code(code: str) -> tuple[int, int] | None:
    """Return ``(door, locknumber)`` for a cloud lock code, or None if unknown."""
    code = (code or "").strip()
    for pattern in _LOCK_CODE_RES:
        match = pattern.match(code)
        if match:
            return int(match.group("door")), int(match.group("lock"))
    return None


class BalterApiError(Exception):
    """Generic error raised when a Quvii Cloud request fails."""


class BalterAuthError(BalterApiError):
    """Raised when authentication credentials are rejected."""


class BalterCloudClient:
    """Async HTTP client for the Quvii Cloud REST and CGI endpoints."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        client_id: str | None = None,
        base_url: str | None = None,
        ssl: bool = False,
    ) -> None:
        """Initialise the cloud client for one account."""
        self._session = session
        self._email = email
        self._password = password
        # Ohne uebergebene Identitaet eine eigene erzeugen -- niemals eine
        # feste, von allen Installationen geteilte ID verwenden.
        self._client_id = client_id or secrets.token_hex(8)
        # Fallback base; the real userapp endpoint is resolved via discovery at login time.
        self._base = URL(base_url or f"https://{HOST}{BASE_PATH}")
        self._base_pinned = base_url is not None
        self._discovered = False
        self._ssl = ssl
        self._jsessionid: str | None = None
        self._server_session: str | None = None
        # duid -> (abgerufen_um, {dynamic_password, data_encode_key, out_auth_code})
        self._cred_cache: dict[str, tuple[float, dict[str, str]]] = {}
        # Laeuft eine Hintergrundauffrischung, haelt diese Referenz sie am Leben --
        # asyncio sammelt sonst nicht referenzierte Tasks unter Umstaenden ein.
        self._refresh_task: asyncio.Task[None] | None = None

    @property
    def client_id(self) -> str:
        """Return the 16-hex identity this client authenticates with."""
        return self._client_id

    # ----------------------------------------------------------------- headers

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        hdr = {
            # Der userapp-Host wird per Discovery aufgeloest und ist NICHT fest --
            # ein hartkodierter Host-Header wuerde nach einem Serverwechsel an den
            # falschen virtuellen Host gehen.
            "Host": self._base.host or HOST,
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        if content_type:
            hdr["Content-Type"] = content_type
        if self._jsessionid:
            hdr["Cookie"] = f"jsessionid={self._jsessionid}"
        return hdr

    def _remember_cookie(self, resp: aiohttp.ClientResponse) -> None:
        for cookie_header in resp.headers.getall("Set-Cookie", []):
            for part in cookie_header.split(";"):
                part = part.strip()
                if part.lower().startswith("jsessionid="):
                    self._jsessionid = part.split("=", 1)[1]

    def _client_block(self) -> str:
        return (
            "<client>"
            f"<app>{APP_ID}</app>"
            f"<id>{self._client_id}</id>"
            f"<oem>{OEM_ID}</oem>"
            f"<type>{CLIENT_TYPE}</type>"
            "</client>"
        )

    @staticmethod
    def _xml_text(root: ET.Element, path: str, default: str = "") -> str:
        el = root.find(path)
        if el is None or el.text is None:
            return default
        return el.text

    def _safe_parse_xml(self, text: str, context: str) -> ET.Element:
        if not text or not text.strip().startswith("<"):
            raise BalterApiError(f"{context}: Invalid non-XML response: {text[:200]}")
        try:
            return ET.fromstring(text)
        except ET.ParseError as err:
            raise BalterApiError(f"{context}: XML parse error ({err}): {text[:200]}") from err

    # ------------------------------------------------------- session handling

    # Die Cloud laesst eine jsessionid nur wenige Minuten leben und beantwortet
    # Anfragen mit abgelaufener Sitzung mit HTTP 404 (nicht 401!). Ohne erneuten
    # Login lieferte get_device_list() dann dauerhaft nichts mehr -- die Folge war
    # ein leeres dynamic_password und ein P2P-LOGIN, den die Tuerstation stumm
    # ablehnt. Darum: bei diesen Antworten genau einmal neu anmelden und die
    # Anfrage wiederholen.
    _SESSION_ERROR_STATUS = frozenset({401, 403, 404})

    async def _relogin(self, context: str, reason: str) -> None:
        """Discard the current session and authenticate again."""
        _LOGGER.debug("%s: cloud session invalid (%s) -- logging in again", context, reason)
        self._server_session = None
        # Der userapp-Endpunkt wandert pro Account/Zeit; nach einem Sitzungsverlust
        # neu aufloesen, statt einen womoeglich veralteten Host weiterzubenutzen.
        self._discovered = False
        await self.login()

    def _forget_session_cookie(self) -> None:
        """Drop the session cookie -- ours AND the copy aiohttp keeps.

        Home Assistant's shared client session has a cookie jar of its own and
        replays it on every request. Forgetting only our copy is not enough: the
        expired jsessionid would still be sent, the server would consider the
        session present and answer without a ``Set-Cookie`` -- the bootstrap then
        failed with "Could not obtain an anonymous session cookie" and the
        integration stayed logged out until Home Assistant restarted (observed
        live after ~30 minutes idle).
        """
        self._jsessionid = None
        host = self._base.host
        if host:
            with contextlib.suppress(AttributeError, TypeError):
                self._session.cookie_jar.clear_domain(host)

    def _cookie_from_jar(self) -> str | None:
        """Return the session cookie aiohttp stored for the current endpoint."""
        with contextlib.suppress(AttributeError, TypeError):
            for name, morsel in self._session.cookie_jar.filter_cookies(self._base).items():
                if name.lower() == "jsessionid":
                    return morsel.value
        return None

    async def _post(
        self,
        build_body: Callable[[], bytes],
        content_type: str,
        context: str,
        body_rejected: Callable[[str], bool] | None = None,
    ) -> str:
        """POST an authenticated request, renewing the session once if it expired.

        ``build_body`` is a callable rather than a ready-made body because the
        request carries ``self._server_session``, which changes on re-login.
        ``body_rejected`` inspects a HTTP-200 response and reports whether the
        server refused it -- some session errors arrive that way, not as a status.
        """
        if not self._server_session:
            await self.login()

        for attempt in (1, 2):
            # Netzfehler als BalterApiError weiterreichen: die Aufrufer behandeln
            # eine unerreichbare Cloud sonst nicht (Gerateliste faellt nicht auf
            # den Cache zurueck, die Hintergrundauffrischung stirbt mit Traceback).
            try:
                async with self._session.post(
                    self._base,
                    data=build_body(),
                    headers=self._headers(content_type),
                    ssl=self._ssl,
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ) as resp:
                    self._remember_cookie(resp)
                    text = await resp.text()
                    status = resp.status
            except (aiohttp.ClientError, TimeoutError) as err:
                raise BalterApiError(f"{context}: {err}") from err

            if status == 200:
                if attempt == 1 and body_rejected is not None and body_rejected(text):
                    await self._relogin(context, "request rejected")
                    continue
                return text
            if attempt == 1 and status in self._SESSION_ERROR_STATUS:
                await self._relogin(context, f"HTTP {status}")
                continue
            raise BalterApiError(f"{context} HTTP {status}: {text[:300]}")

        raise BalterApiError(f"{context}: session could not be renewed")

    # -------------------------------------------------------------- discovery

    async def _discover_userapp(self) -> None:
        """Resolve the per-account userapp REST endpoint via the discovery service.

        The userapp host is announced by ``global.qvcloud.net/mst/query`` and is not
        stable across accounts/time, so we never hardcode it. Falls back silently to
        the configured ``self._base`` if discovery is unavailable.
        """
        if self._discovered or self._base_pinned:
            return
        body = (
            '<?xml version="1.0" encoding="UTF-8"?><envelope><header>'
            "<flag>tdkcloud</flag><command>query-hlrv2</command><seq>1</seq></header>"
            "<content><server-type>userapp</server-type>"
            f"<oem>{OEM_ID}</oem><devid></devid><public-ip></public-ip>"
            f"<client-id>{self._client_id}</client-id><regionid>0</regionid>"
            f"<version>{CLIENT_VERSION}</version></content></envelope>"
        )
        try:
            async with self._session.get(
                f"https://{DISCOVERY_HOST}{DISCOVERY_PATH}",
                data=body.encode("utf-8"),
                headers={"Host": DISCOVERY_HOST, "Content-Type": "application/xml;charset=utf-8"},
                ssl=self._ssl,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ) as resp:
                text = await resp.text()
            root = self._safe_parse_xml(text, "discovery")
            for srv in root.findall(".//server"):
                if (srv.findtext("server-type") or "") != "userapp":
                    continue
                url = (srv.findtext("url") or "").strip()
                uri = (srv.findtext("uri") or "").strip()
                if url:
                    base = URL(url)
                    self._base = base / uri.lstrip("/") if uri else base
                    self._discovered = True
                    _LOGGER.debug("Resolved userapp endpoint: %s", self._base)
                break
        except (aiohttp.ClientError, BalterApiError, TimeoutError) as err:
            _LOGGER.debug("Userapp discovery failed, using fallback %s: %s", self._base, err)

    # --------------------------------------------------------------- bootstrap

    async def _bootstrap_session(self) -> None:
        """Obtain a fresh anonymous jsessionid for the resolved endpoint."""
        self._forget_session_cookie()
        try:
            async with self._session.get(
                self._base,
                headers=self._headers(),
                ssl=self._ssl,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ) as resp:
                self._remember_cookie(resp)
                await resp.read()
        except (aiohttp.ClientError, TimeoutError) as err:
            raise BalterApiError(f"Could not reach {self._base}: {err}") from err
        # Manche Antworten tragen das Cookie nur im Jar (Redirect-Kette); von dort
        # holen, bevor wir aufgeben.
        if not self._jsessionid:
            self._jsessionid = self._cookie_from_jar()
        if not self._jsessionid:
            raise BalterApiError("Could not obtain an anonymous session cookie")

    # ------------------------------------------------------------------ login

    async def login(self) -> None:
        """Authenticate and establish a jsessionid session."""
        await self._discover_userapp()
        await self._bootstrap_session()
        body = (
            '<?xml version="1.0" encoding="UTF-8"?><envelope>'
            '<content class="com.quvii.qvweb.userauth.bean.request.LoginReqContent">'
            f"<account>{_xml_escape(self._email)}</account>"
            "<auth-code></auth-code>"
            f"<ip-region-id>{IP_REGION_ID}</ip-region-id>"
            f"<password>{_sha256(self._password)}</password>"
            "<auth-type>0</auth-type>"
            "</content>"
            "<header>"
            f"{self._client_block()}"
            "<command>login</command><flag>tdkcloud</flag><seq>1</seq>"
            "<user-data></user-data>"
            f"<version>{CLIENT_VERSION}</version>"
            "</header>"
            "</envelope>"
        )
        try:
            async with self._session.post(
                self._base,
                data=body.encode("utf-8"),
                headers=self._headers("application/xml"),
                ssl=self._ssl,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ) as resp:
                self._remember_cookie(resp)
                text = await resp.text()
                if resp.status != 200:
                    raise BalterApiError(f"Login HTTP {resp.status}: {text[:300]}")
        except (aiohttp.ClientError, TimeoutError) as err:
            raise BalterApiError(f"Login could not reach {self._base}: {err}") from err

        root = self._safe_parse_xml(text, "login")
        result = self._xml_text(root, "./header/result", "-1")
        if result != "0":
            raise BalterAuthError(f"Login rejected by server (result={result})")
        self._server_session = self._xml_text(root, "./header/session/id", "")
        if not self._jsessionid:
            raise BalterApiError("Login succeeded but no session cookie was returned")

    # ------------------------------------------------------------- device list

    def _device_list_body(self) -> bytes:
        return (
            '<?xml version="1.0" encoding="UTF-8"?><envelope>'
            '<content class="com.quvii.qvweb.userauth.bean.request.DevListReqContent">'
            "<count>128</count><filter></filter>"
            "<manual-accept-device-share>1</manual-accept-device-share>"
            "<order>0</order><owner></owner><page>0</page>"
            "</content>"
            "<header>"
            f"{self._client_block()}"
            "<command>get-device-list</command><flag>tdkcloud</flag><seq>4</seq>"
            f"<session>{_xml_escape(self._server_session or '')}</session>"
            "</header>"
            "</envelope>"
        ).encode()

    # Beide Endpunkte melden eine abgelaufene Sitzung als HTTP 200 mit einem
    # Fehler-``result`` im Rumpf (JSON: 100100001) -- ohne diese Pruefung waere
    # die Antwort von einem leeren, aber gueltigen Ergebnis nicht zu unterscheiden.
    @staticmethod
    def _xml_result_rejected(text: str) -> bool:
        """Report whether an XML envelope carries a non-zero ``header/result``."""
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return False
        el = root.find("./header/result")
        return el is not None and (el.text or "0") != "0"

    @staticmethod
    def _json_result_rejected(text: str) -> bool:
        """Report whether a JSON envelope carries a non-zero ``header.result``."""
        try:
            data = json.loads(text)
        except ValueError:
            return False
        if not isinstance(data, dict):
            return False
        return (data.get("header") or {}).get("result", 0) not in (0, "0")

    async def get_device_list(self) -> list[dict]:
        """Return all devices bound to the account."""
        text = await self._post(
            self._device_list_body,
            "application/xml",
            "get-device-list",
            body_rejected=self._xml_result_rejected,
        )

        root = self._safe_parse_xml(text, "get-device-list")
        result = self._xml_text(root, "./header/result", "0")
        if result != "0":
            raise BalterApiError(f"get-device-list rejected by server (result={result})")

        devices = []
        for dev in root.findall("./content/device"):
            devices.append(
                {
                    "duid": self._xml_text(dev, "id"),
                    "name": self._xml_text(dev, "name"),
                    "model": self._xml_text(dev, "model"),
                    "dynamic_password": self._xml_text(dev, "dynamic-password"),
                    "out_auth_code": self._xml_text(dev, "out-auth-code"),
                    "data_encode_key": self._xml_text(dev, "data-encode-key"),
                }
            )

        # Jede Geraeteliste traegt die rotierenden Geheimnisse schon bei sich --
        # den Cache hier fuellen, damit der Setup-Abruf ihn mitwaermt und ein
        # spaeterer Cloud-Ausfall auf echte (wenn auch aeltere) Werte zurueckfaellt
        # statt auf leere Strings.
        now = time.time()
        for device in devices:
            if not device["duid"]:
                continue
            self._cred_cache[device["duid"]] = (
                now,
                {
                    "dynamic_password": device.get("dynamic_password") or "",
                    "data_encode_key": device.get("data_encode_key") or "",
                    "out_auth_code": device.get("out_auth_code") or "",
                },
            )
        return devices

    # ------------------------------------------------------------ sub-devices

    async def get_subdev_list(self, duid: str) -> list[dict]:
        """Return the lock sub-devices for one device."""
        def build_body() -> bytes:
            return json.dumps(
                {
                    "content": {"duids": [duid]},
                    "header": {
                        "client": {
                            "app": APP_ID,
                            "id": self._client_id,
                            "oem": OEM_ID,
                            "type": int(CLIENT_TYPE),
                        },
                        "command": "get-subdev-list",
                        "flag": "tdkcloud",
                        "seq": 5,
                        "session": self._server_session,
                        "user-data": "",
                        "version": CLIENT_VERSION,
                    },
                }
            ).encode("utf-8")

        text = await self._post(
            build_body,
            "application/json;charset=utf-8",
            "get-subdev-list",
            body_rejected=self._json_result_rejected,
        )
        try:
            data = json.loads(text)
        except ValueError as err:
            raise BalterApiError(
                f"get-subdev-list: invalid JSON response ({err}): {text[:200]}"
            ) from err

        result = (data.get("header") or {}).get("result", 0)
        if result not in (0, "0"):
            raise BalterApiError(f"get-subdev-list rejected by server (result={result})")

        locks = []
        for entry in data.get("content", []):
            sub_devlist = entry.get("sub-devlist", [])
            enabled_doors = {
                sub.get("id")
                for sub in sub_devlist
                if sub.get("type") == "chn" and sub.get("enable")
            }
            for sub in sub_devlist:
                if sub.get("type") != "lock":
                    continue
                parsed = _parse_lock_code(sub.get("code", ""))
                if parsed is None:
                    continue
                door, locknumber = parsed
                if enabled_doors and door not in enabled_doors:
                    continue
                locks.append(
                    {
                        # Kanonischer Code: die unique_id der Entities haengt daran,
                        # darum unabhaengig vom Schreibstil des Geraets normieren.
                        "code": f"door{door}-lock{locknumber}",
                        "name": sub.get("name") or f"door{door}-lock{locknumber}",
                        "door": door,
                        "locknumber": locknumber,
                    }
                )
        return locks

    # --------------------------------------------------------------- helpers

    async def get_device_credentials(
        self, duid: str, max_age: float = CREDENTIAL_MAX_AGE, *, allow_stale: bool = False
    ) -> dict[str, str]:
        """Return the rotating per-device secrets, refreshed from the cloud.

        ``dynamic_password`` and ``data_encode_key`` both rotate roughly weekly;
        a stale pair makes the P2P login fail and the video stream undecodable.
        Reading them once at setup is therefore not enough. Results are cached
        for ``max_age`` seconds so a burst of snapshots does not hammer the API.

        ``allow_stale`` hands back a cached pair up to ``CREDENTIAL_STALE_AGE``
        old immediately and refreshes it in the background instead. Callers on a
        latency-critical path -- opening a door -- want that: the secrets rotate
        weekly, so a few hours are irrelevant, while a slow or unreachable cloud
        would otherwise delay the unlock by seconds for nothing.

        Returns ``{"dynamic_password", "data_encode_key", "out_auth_code"}``;
        values may be empty strings if the cloud is unreachable and nothing was
        cached earlier. Callers must treat an empty ``dynamic_password`` as a
        hard error -- the device rejects such a P2P login without any reply.
        """
        cached = self._cred_cache.get(duid)
        if cached and (time.time() - cached[0]) < max_age:
            return cached[1]
        if allow_stale and cached and (time.time() - cached[0]) < CREDENTIAL_STALE_AGE:
            # Kurz auf die Auffrischung warten, aber nicht auf sie angewiesen sein.
            # Ohne das wuerde in der Woche, in der die Geheimnisse rotieren, ein
            # Oeffnen mit totem Passwort losgeschickt -- das Geraet quittiert einen
            # solchen LOGIN und laesst die Sitzung dann stumm verfallen.
            await self._refresh_credentials_briefly()
            return self._cred_cache.get(duid, cached)[1]

        try:
            await self.get_device_list()   # fuellt _cred_cache fuer alle Geraete
        except BalterApiError as err:
            if cached:
                # Lieber alt als gar nichts: die Geheimnisse rotieren nur
                # woechentlich, ein paar Stunden Cache sind meist noch gueltig.
                _LOGGER.warning(
                    "Could not refresh device credentials for %s (%s) -- using the "
                    "cached pair from %.0f min ago",
                    duid, err, (time.time() - cached[0]) / 60,
                )
                return cached[1]
            _LOGGER.warning("Could not refresh device credentials for %s: %s", duid, err)
            return {"dynamic_password": "", "data_encode_key": "", "out_auth_code": ""}

        refreshed = self._cred_cache.get(duid)
        if refreshed is None:
            _LOGGER.warning(
                "Device %s is no longer listed on the cloud account", duid
            )
            return {"dynamic_password": "", "data_encode_key": "", "out_auth_code": ""}
        return refreshed[1]

    def _refresh_credentials_soon(self) -> asyncio.Task[None] | None:
        """Refresh the cached device secrets in the background, one run at a time."""
        if self._refresh_task is not None and not self._refresh_task.done():
            return self._refresh_task
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return None
        self._refresh_task = loop.create_task(self._refresh_credentials())
        return self._refresh_task

    async def _refresh_credentials_briefly(self) -> None:
        """Give a background refresh a short head start, then carry on regardless."""
        task = self._refresh_credentials_soon()
        if task is None:
            return
        # shield: laeuft der Task fuer einen anderen Aufrufer weiter, darf unser
        # Timeout ihn nicht abbrechen.
        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(task), CREDENTIAL_REFRESH_WAIT)

    async def _refresh_credentials(self) -> None:
        """Pull a fresh device list; a temporarily unreachable cloud is not fatal."""
        try:
            await self.get_device_list()
        except (BalterApiError, aiohttp.ClientError, TimeoutError) as err:
            # Der Aufrufer arbeitet bereits mit dem zwischengespeicherten Paar
            # weiter -- hier ist nichts zu retten und nichts zu melden. Fangen
            # muessen wir es trotzdem: eine unbeaufsichtigte Task wuerde den
            # Fehler sonst als Traceback ins Log kippen.
            _LOGGER.debug("Background credential refresh failed: %s", err)

    async def async_close(self) -> None:
        """Cancel a running background refresh (called when the entry unloads)."""
        task = self._refresh_task
        self._refresh_task = None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    async def get_dynamic_password(self, duid: str) -> str:
        """Return the current rotating device password, or "" if unavailable.

        There is deliberately no offline fallback: a made-up password is
        indistinguishable from a correct one at the transport layer -- the
        device acks the P2P login and then silently drops the session, which
        looks like a busy door station instead of an auth failure.
        """
        creds = await self.get_device_credentials(duid)
        return creds.get("dynamic_password") or ""

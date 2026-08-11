"""Minimal client for the Quvii/Homaxi "tdkcloud" cloud API used by the Balter EVO app.

Reverse-engineered by capturing real app traffic (see REVERSE_ENGINEERING_NOTES.md).
Every request/response shape here was observed directly from the live app, not guessed.

Key insight (solves the former "404" blocker): the login POST only works inside an
already-established servlet session. The client must first do a plain ``GET /auth/user``
to receive an anonymous ``jsessionid`` cookie, and must POST to the plain ``/auth/user``
path (NOT the ``;jus_duplex=up`` matrix-parameter variant, which routes into a duplex
long-poll tunnel that answers with empty ACKs). With those two fixes the whole flow —
login, device list, sub-device list, unlock — works synchronously from a plain HTTP
client, no client certificate or TLS fingerprinting workaround required.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import xml.etree.ElementTree as ET

import aiohttp

from .const import (
    APP_ID,
    CLIENT_TYPE,
    CLIENT_VERSION,
    HOST,
    IP_REGION_ID,
    OEM_ID,
    REQUEST_TIMEOUT,
    USER_AGENT,
)

_LOGGER = logging.getLogger(__name__)


class BalterApiError(Exception):
    """Raised when the cloud API returns an error or an unexpected response."""


class BalterAuthError(BalterApiError):
    """Raised when login fails (wrong credentials)."""


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


class BalterCloudClient:
    """Talks to the Quvii cloud (qvcloud.net) on behalf of one Balter/Quvii account."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        email: str,
        password: str,
        client_id: str | None = None,
    ) -> None:
        self._session = session
        self._email = email
        self._password = password
        self._client_id = client_id or f"003-{APP_ID}-{secrets.token_hex(8)}"
        self._jsessionid: str | None = None
        self._server_session: str = ""

    # ------------------------------------------------------------------ helpers

    @property
    def _base(self) -> str:
        return f"https://{HOST}/auth/user"

    def _client_block(self) -> str:
        return (
            "<client>"
            f"<app>{APP_ID}</app><id>{self._client_id}</id>"
            f"<oem>{OEM_ID}</oem><type>{CLIENT_TYPE}</type>"
            "</client>"
        )

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT}
        if content_type:
            headers["Content-Type"] = content_type
        if self._jsessionid:
            headers["Cookie"] = f"jsessionid={self._jsessionid}"
        return headers

    def _remember_cookie(self, response: aiohttp.ClientResponse) -> None:
        set_cookie = response.headers.get("Set-Cookie")
        if set_cookie and "jsessionid=" in set_cookie:
            value = set_cookie.split("jsessionid=", 1)[1].split(";", 1)[0]
            self._jsessionid = value

    @staticmethod
    def _xml_text(root: ET.Element, path: str, default: str = "") -> str:
        el = root.find(path)
        if el is None or el.text is None:
            return default
        return el.text

    # --------------------------------------------------------------- bootstrap

    async def _bootstrap_session(self) -> None:
        """Obtain an anonymous jsessionid.

        The login POST returns HTTP 404 unless a servlet session already exists, so we
        must first do a plain GET that makes the server issue a ``Set-Cookie: jsessionid``.
        """
        async with self._session.get(
            self._base,
            headers=self._headers(),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            await resp.read()
        if not self._jsessionid:
            raise BalterApiError("Could not obtain an anonymous session cookie")

    # ------------------------------------------------------------------ login

    async def login(self) -> None:
        """Authenticate and establish a jsessionid session. Raises BalterAuthError on failure."""
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
        async with self._session.post(
            self._base,
            data=body.encode("utf-8"),
            headers=self._headers("application/xml"),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            text = await resp.text()
            if resp.status != 200:
                raise BalterApiError(f"Login HTTP {resp.status}: {text[:300]}")

        root = ET.fromstring(text)
        result = self._xml_text(root, "./header/result", "-1")
        if result != "0":
            raise BalterAuthError(f"Login rejected by server (result={result})")
        self._server_session = self._xml_text(root, "./header/session/id", "")
        if not self._jsessionid:
            raise BalterApiError("Login succeeded but no session cookie was returned")

    # ------------------------------------------------------------- device list

    async def get_device_list(self) -> list[dict]:
        """Return all devices bound to the account, including the rotating device password."""
        body = (
            '<?xml version="1.0" encoding="UTF-8"?><envelope>'
            '<content class="com.quvii.qvweb.userauth.bean.request.DevListReqContent">'
            "<count>128</count><filter></filter>"
            "<manual-accept-device-share>1</manual-accept-device-share>"
            "<order>0</order><owner></owner><page>0</page>"
            "</content>"
            "<header>"
            f"{self._client_block()}"
            "<command>get-device-list</command><flag>tdkcloud</flag><seq>4</seq>"
            f"<session>{_xml_escape(self._server_session)}</session>"
            "</header>"
            "</envelope>"
        )
        async with self._session.post(
            self._base,
            data=body.encode("utf-8"),
            headers=self._headers("application/xml"),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            text = await resp.text()
            if resp.status != 200:
                raise BalterApiError(f"get-device-list HTTP {resp.status}: {text[:300]}")

        root = ET.fromstring(text)
        devices = []
        for dev in root.findall("./content/device"):
            devices.append(
                {
                    "duid": self._xml_text(dev, "id"),
                    "name": self._xml_text(dev, "name"),
                    "model": self._xml_text(dev, "model"),
                    "dynamic_password": self._xml_text(dev, "dynamic-password"),
                    # SHA256 of the currently configured door PIN (server-side copy).
                    "out_auth_code": self._xml_text(dev, "out-auth-code"),
                    # Per-device key that also protects the P2P media stream.
                    "data_encode_key": self._xml_text(dev, "data-encode-key"),
                }
            )
        return devices

    # ------------------------------------------------------------ sub-devices

    async def get_subdev_list(self, duid: str) -> list[dict]:
        """Return the lock sub-devices (door channel + lock number) for one device."""
        body = {
            "content": {"duids": [duid]},
            "header": {
                "client": {"app": APP_ID, "id": self._client_id, "oem": OEM_ID, "type": 3},
                "command": "get-subdev-list",
                "flag": "tdkcloud",
                "seq": 5,
                "session": self._server_session,
                "user-data": "",
                "version": CLIENT_VERSION,
            },
        }
        async with self._session.post(
            self._base,
            data=json.dumps(body).encode("utf-8"),
            headers=self._headers("application/json;charset=utf-8"),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            data = await resp.json(content_type=None)
            if resp.status != 200:
                raise BalterApiError(f"get-subdev-list HTTP {resp.status}: {data}")

        locks = []
        for entry in data.get("content", []):
            sub_devlist = entry.get("sub-devlist", [])
            # The device reports 16 lock sub-devices (8 channels x 2 locks) regardless of
            # what is physically wired. Only channels marked enabled correspond to a real
            # door station, so restrict the locks we surface to those channels.
            enabled_doors = {
                sub.get("id")
                for sub in sub_devlist
                if sub.get("type") == "chn" and sub.get("enable")
            }
            for sub in sub_devlist:
                if sub.get("type") != "lock" or not sub.get("enable"):
                    continue
                code = sub.get("code", "")
                # code looks like "lock_chn<door> <locknumber>", e.g. "lock_chn1 2"
                try:
                    chn_part, lock_part = code.rsplit(" ", 1)
                    door = int(chn_part.replace("lock_chn", ""))
                    locknumber = int(lock_part)
                except (ValueError, IndexError):
                    continue
                if enabled_doors and door not in enabled_doors:
                    continue
                locks.append(
                    {
                        "code": code,
                        "name": sub.get("name", code),
                        "door": door,
                        "locknumber": locknumber,
                    }
                )
        return locks

    # --------------------------------------------------------------- unlock

    async def open_lock(
        self, dynamic_password: str, door: int, locknumber: int, pin: str
    ) -> None:
        """Send the door-open command. Raises BalterApiError if the device rejects it."""
        body = (
            "<envelope>"
            '<content class="com.quvii.qvweb.device.bean.requset.DeviceUnlockContent">'
            f"<door>{door}</door>"
            f"<locknumber>{locknumber}</locknumber>"
            f"<password>{_sha256(pin)}</password>"
            "</content>"
            "<header>"
            f"<password>{_xml_escape(dynamic_password)}</password>"
            "<security>username</security>"
            "</header>"
            "<command>set.device.opendoor</command>"
            "</envelope>"
        )
        url = f"https://{HOST}/tdkcgi"
        async with self._session.post(
            url,
            data=body.encode("utf-8"),
            headers=self._headers("application/xml; charset=UTF-8"),
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            text = await resp.text()
            if resp.status != 200:
                raise BalterApiError(f"open_lock HTTP {resp.status}: {text[:300]}")

        root = ET.fromstring(text)
        error = self._xml_text(root, "./body/error", "-1")
        if error != "0":
            raise BalterApiError(f"Device rejected unlock command (error={error})")

    # --------------------------------------------------------------- helpers

    async def get_dynamic_password(self, duid: str) -> str:
        """Return a fresh rotating device password for one device.

        Re-authenticates first: the servlet session can expire sooner than the device
        password (which is valid ~1 week), and login is only two cheap requests, so a
        fresh login before every unlock keeps the call reliable.
        """
        await self.login()
        for device in await self.get_device_list():
            if device["duid"] == duid:
                if not device["dynamic_password"]:
                    raise BalterApiError(f"No dynamic password for device {duid}")
                return device["dynamic_password"]
        raise BalterApiError(f"Device {duid} no longer listed on the account")

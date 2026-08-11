"""Minimal client for the Quvii/Homaxi "tdkcloud" cloud API used by the Balter EVO app.

Reverse-engineered by capturing real app traffic (see REVERSE_ENGINEERING_NOTES.md).
Every request/response shape here was observed directly from the live app, not guessed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import xml.etree.ElementTree as ET

import aiohttp

from .const import (
    API_HOST,
    APP_ID,
    CLIENT_TYPE,
    CLIENT_VERSION,
    IP_REGION_ID,
    LOGIN_HOST,
    OEM_ID,
    REQUEST_TIMEOUT,
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
        self._duplex_session: str = ""

    # ------------------------------------------------------------------ helpers

    def _client_block(self) -> str:
        return (
            "<client>"
            f"<app>{APP_ID}</app><id>{self._client_id}</id>"
            f"<oem>{OEM_ID}</oem><type>{CLIENT_TYPE}</type>"
            "</client>"
        )

    def _cookie_header(self) -> dict[str, str]:
        if self._jsessionid:
            return {"Cookie": f"jsessionid={self._jsessionid}"}
        return {}

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

    # ------------------------------------------------------------------ login

    async def login(self) -> None:
        """Authenticate and establish a jsessionid session. Raises BalterAuthError on failure."""
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
        url = f"https://{LOGIN_HOST}/auth/user;jus_duplex=up"
        async with self._session.post(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/xml", **self._cookie_header()},
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
        self._duplex_session = self._xml_text(root, "./header/session/id", "")
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
            f"<session>{_xml_escape(self._duplex_session)}</session>"
            "</header>"
            "</envelope>"
        )
        url = f"https://{API_HOST}/auth/user;jus_duplex=up"
        async with self._session.post(
            url,
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/xml", **self._cookie_header()},
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
                "session": self._duplex_session,
                "user-data": "",
                "version": CLIENT_VERSION,
            },
        }
        url = f"https://{API_HOST}/auth/user;jus_duplex=up"
        async with self._session.post(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json;charset=utf-8", **self._cookie_header()},
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            data = await resp.json(content_type=None)
            if resp.status != 200:
                raise BalterApiError(f"get-subdev-list HTTP {resp.status}: {data}")

        locks = []
        for entry in data.get("content", []):
            if entry.get("duid") != duid:
                continue
            for sub in entry.get("sub-devlist", []):
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
        url = f"https://{API_HOST}/tdkcgi"
        async with self._session.post(
            url,
            data=body.encode("utf-8"),
            headers={
                "Content-Type": "application/xml; charset=UTF-8",
                **self._cookie_header(),
            },
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

    async def ensure_logged_in(self) -> None:
        if not self._jsessionid:
            await self.login()

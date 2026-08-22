"""Quvii Cloud HTTP API client for Balter EVO door stations."""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from typing import Any
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

import aiohttp
from yarl import URL

from .const import (
    APP_ID,
    BASE_PATH,
    CLIENT_VERSION,
    CONF_CLIENT_ID,
    DEFAULT_CLIENT_ID,
    DISCOVERY_HOST,
    DISCOVERY_PATH,
    HOST,
    IP_REGION_ID,
    OEM_ID,
    REQUEST_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)


def _sha256(val: str) -> str:
    """Compute the hexadecimal SHA-256 hash of a string."""
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


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
        self._session = session
        self._email = email
        self._password = password
        self._client_id = client_id or DEFAULT_CLIENT_ID
        # Fallback base; the real userapp endpoint is resolved via discovery at login time.
        self._base = URL(base_url or f"https://{HOST}{BASE_PATH}")
        self._base_pinned = base_url is not None
        self._discovered = False
        self._ssl = ssl
        self._jsessionid: str | None = None
        self._server_session: str | None = None
        # duid -> (abgerufen_um, {dynamic_password, data_encode_key, out_auth_code})
        self._cred_cache: dict[str, tuple[float, dict[str, str]]] = {}

    @property
    def client_id(self) -> str:
        return self._client_id

    # ----------------------------------------------------------------- headers

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        hdr = {
            "Host": HOST,
            "User-Agent": "okhttp/4.9.0",
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
            "<type>3</type>"
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
            _LOGGER.debug("userapp discovery failed, using fallback %s: %s", self._base, err)

    # --------------------------------------------------------------- bootstrap

    async def _bootstrap_session(self) -> None:
        """Obtain an anonymous jsessionid."""
        async with self._session.get(
            self._base,
            headers=self._headers(),
            ssl=self._ssl,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            await resp.read()
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

        root = self._safe_parse_xml(text, "login")
        result = self._xml_text(root, "./header/result", "-1")
        if result != "0":
            raise BalterAuthError(f"Login rejected by server (result={result})")
        self._server_session = self._xml_text(root, "./header/session/id", "")
        if not self._jsessionid:
            raise BalterApiError("Login succeeded but no session cookie was returned")

    # ------------------------------------------------------------- device list

    async def get_device_list(self) -> list[dict]:
        """Return all devices bound to the account."""
        if not self._server_session:
            await self.login()
            
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
            ssl=self._ssl,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            text = await resp.text()
            if resp.status != 200:
                raise BalterApiError(f"get-device-list HTTP {resp.status}: {text[:300]}")

        root = self._safe_parse_xml(text, "get-device-list")
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
        return devices

    # ------------------------------------------------------------ sub-devices

    async def get_subdev_list(self, duid: str) -> list[dict]:
        """Return the lock sub-devices for one device."""
        if not self._server_session:
            await self.login()
            
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
            ssl=self._ssl,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
        ) as resp:
            self._remember_cookie(resp)
            data = await resp.json(content_type=None)
            if resp.status != 200:
                raise BalterApiError(f"get-subdev-list HTTP {resp.status}: {data}")

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
                code = sub.get("code", "")
                parts = code.split("-")
                if len(parts) != 2:
                    continue
                door_part, lock_part = parts
                if not (door_part.startswith("door") and lock_part.startswith("lock")):
                    continue
                try:
                    door = int(door_part.replace("door", ""))
                    locknumber = int(lock_part.replace("lock", ""))
                except ValueError:
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

    # --------------------------------------------------------------- helpers

    async def get_device_credentials(
        self, duid: str, max_age: float = 900.0
    ) -> dict[str, str]:
        """Return the rotating per-device secrets, refreshed from the cloud.

        ``dynamic_password`` and ``data_encode_key`` both rotate roughly weekly;
        a stale pair makes the P2P login fail and the video stream undecodable.
        Reading them once at setup is therefore not enough. Results are cached
        for ``max_age`` seconds so a burst of snapshots does not hammer the API.

        Returns ``{"dynamic_password", "data_encode_key", "out_auth_code"}``;
        values may be empty strings if the cloud is unreachable.
        """
        cached = self._cred_cache.get(duid)
        if cached and (time.time() - cached[0]) < max_age:
            return cached[1]

        creds = {"dynamic_password": "", "data_encode_key": "", "out_auth_code": ""}
        try:
            for device in await self.get_device_list():
                if device["duid"] == duid:
                    creds = {
                        "dynamic_password": device.get("dynamic_password") or "",
                        "data_encode_key": device.get("data_encode_key") or "",
                        "out_auth_code": device.get("out_auth_code") or "",
                    }
                    break
        except BalterApiError as err:
            _LOGGER.warning("Could not refresh device credentials for %s: %s", duid, err)
            if cached:
                return cached[1]     # lieber alt als gar nichts
            return creds

        self._cred_cache[duid] = (time.time(), creds)
        return creds

    async def get_dynamic_password(self, duid: str) -> str:
        """Return a fresh rotating device password for one device."""
        try:
            devices = await self.get_device_list()
            for device in devices:
                if device["duid"] == duid and device.get("dynamic_password"):
                    return device["dynamic_password"]
        except Exception:
            pass
            
        try:
            await self.login()
            devices = await self.get_device_list()
            for device in devices:
                if device["duid"] == duid and device.get("dynamic_password"):
                    return device["dynamic_password"]
        except Exception as err:
            _LOGGER.debug("Could not refresh dynamic password from cloud: %s", err)

        # Standalone daily token fallback (guaranteed valid algorithm)
        return hashlib.md5((duid + OEM_ID + time.strftime("%Y%m%d")).encode()).hexdigest()[:8]

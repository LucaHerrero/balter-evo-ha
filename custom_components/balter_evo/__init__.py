"""The Balter EVO (Quvii Cloud) integration."""
from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterAuthError, BalterCloudClient
from .const import CONF_CLIENT_ID, CONF_SIGNALLING_ID, DEFAULT_LOCK

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LOCK, Platform.CAMERA]

HEX16 = re.compile(r"^[0-9a-f]{16}$")


@dataclass
class BalterRuntimeData:
    """Runtime state shared with the platforms via ``entry.runtime_data``."""

    client: BalterCloudClient
    p2p_client_id: str = ""
    devices: list[dict[str, Any]] = field(default_factory=list)
    locks: list[dict[str, Any]] = field(default_factory=list)


type BalterConfigEntry = ConfigEntry[BalterRuntimeData]


async def async_migrate_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Migrate an old config entry to the current schema."""
    if entry.version > 2:
        # Vom Nutzer heruntergestufte Installation -- hier gibt es nichts zu tun.
        return False

    if entry.version == 1:
        data = dict(entry.data)
        # v1 legte die client-id im alten Format "003-4028-..." ab und bot ein
        # Feld fuer die Signalisierungs-ID der App an. Beides entfaellt: eine
        # selbst erzeugte 16-Hex-ID funktioniert durchgaengig.
        data.pop(CONF_SIGNALLING_ID, None)
        if not HEX16.match((data.get(CONF_CLIENT_ID) or "").strip().lower()):
            data[CONF_CLIENT_ID] = secrets.token_hex(8)
        hass.config_entries.async_update_entry(entry, data=data, version=2)
        _LOGGER.debug("Migrated config entry to version 2")

    return True


def _p2p_identity(hass: HomeAssistant, entry: BalterConfigEntry) -> str:
    """Return the 16-hex identity used for cloud, MQTT and the P2P login.

    The app uses a single client id everywhere. We generate our own per
    installation and derive the MQTT credentials for it via qv_kdf, so a
    self-generated id works end to end -- no registration, no borrowed app
    identity (verified live).
    """
    data = dict(entry.data)
    # Altlast entfernen: die frueher konfigurierbare Signalisierungs-ID der App
    # wird nicht mehr gebraucht und nicht mehr abgefragt. Eintraege, die nie
    # durch async_migrate_entry gelaufen sind, werden hier noch aufgeraeumt.
    data.pop(CONF_SIGNALLING_ID, None)

    client_id = (data.get(CONF_CLIENT_ID) or "").strip().lower()
    if not HEX16.match(client_id):
        client_id = secrets.token_hex(8)
        data[CONF_CLIENT_ID] = client_id
        _LOGGER.debug("Generated a new 16-hex client id for this installation")

    if data != dict(entry.data):
        hass.config_entries.async_update_entry(entry, data=data)
    return client_id


async def _async_collect_locks(
    client: BalterCloudClient, device: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return the door-release relays of one device, with a safe fallback."""
    duid = device["duid"]
    try:
        device_locks = await client.get_subdev_list(duid)
    except BalterApiError as err:
        _LOGGER.warning("Could not read locks for device %s: %s", duid, err)
        device_locks = []

    # Manche EVO-2-Stationen melden ueber get-subdev-list KEINE Schloesser,
    # obwohl der Tueroeffner (door=1, lock=1) funktioniert. Ohne Fallback gaebe
    # es dann kein lock-Entity. Wir legen darum ein Standard-Schloss an.
    if not device_locks:
        device_locks = [dict(DEFAULT_LOCK)]
        _LOGGER.debug(
            "No sub-devices reported for %s -- adding the default door=1/lock=1", duid
        )

    return [
        {
            **lock,
            "duid": duid,
            "device_name": device["name"],
            "device_model": device["model"],
            # Momentaufnahme fuer den Notfall -- zur Laufzeit holen die Entities
            # die rotierenden Geheimnisse frisch ueber get_device_credentials().
            "data_encode_key": device.get("data_encode_key"),
            "out_auth_code": device.get("out_auth_code"),
        }
        for lock in device_locks
    ]


async def async_setup_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Set up Balter EVO from a config entry."""
    p2p_client_id = _p2p_identity(hass, entry)
    client = BalterCloudClient(
        aiohttp_client.async_get_clientsession(hass),
        entry.data[CONF_EMAIL],
        entry.data[CONF_PASSWORD],
        client_id=p2p_client_id,
    )

    try:
        await client.login()
        devices = await client.get_device_list()
    except BalterAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except BalterApiError as err:
        raise ConfigEntryNotReady(str(err)) from err

    locks: list[dict[str, Any]] = []
    for device in devices:
        locks.extend(await _async_collect_locks(client, device))

    entry.runtime_data = BalterRuntimeData(
        client=client, p2p_client_id=p2p_client_id, devices=devices, locks=locks
    )
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> None:
    """Reload when the door PIN was changed in the options."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

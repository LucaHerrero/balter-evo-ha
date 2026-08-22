"""The Balter EVO (Quvii Cloud) integration."""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
import secrets
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterAuthError, BalterCloudClient
from .const import CONF_CLIENT_ID, CONF_SIGNALLING_ID

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LOCK, Platform.CAMERA]


@dataclass
class BalterRuntimeData:
    """Runtime state shared with the platforms via ``entry.runtime_data``."""

    client: BalterCloudClient
    p2p_client_id: str = ""
    devices: list[dict[str, Any]] = field(default_factory=list)
    locks: list[dict[str, Any]] = field(default_factory=list)


type BalterConfigEntry = ConfigEntry[BalterRuntimeData]

HEX16 = re.compile(r"^[0-9a-f]{16}$")


def _p2p_identity(hass: HomeAssistant, entry: BalterConfigEntry) -> str:
    """Return the 16-hex identity used for cloud, MQTT and the P2P login.

    The app uses a single client id everywhere. Ours is generated per
    installation; only the MQTT signalling additionally requires that the id be
    registered with the ust server, which is why a user-supplied app id takes
    precedence (see const.CONF_SIGNALLING_ID).
    """
    signalling = (entry.data.get(CONF_SIGNALLING_ID) or "").strip().lower()
    if HEX16.match(signalling):
        return signalling

    client_id = (entry.data.get(CONF_CLIENT_ID) or "").strip().lower()
    if HEX16.match(client_id):
        return client_id

    # Alteintrag (Format "003-4028-...") oder leer -> eigene Identitaet erzeugen
    # und dauerhaft im Eintrag ablegen.
    client_id = secrets.token_hex(8)
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, CONF_CLIENT_ID: client_id}
    )
    _LOGGER.info("Balter EVO: generated a new 16-hex client id for this installation")
    return client_id


async def async_setup_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Set up Balter EVO from a config entry."""
    session = aiohttp_client.async_get_clientsession(hass)
    p2p_client_id = _p2p_identity(hass, entry)
    client = BalterCloudClient(
        session,
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
        try:
            device_locks = await client.get_subdev_list(device["duid"])
        except BalterApiError as err:
            _LOGGER.warning("Could not read locks for device %s: %s", device["duid"], err)
            continue
        for lock in device_locks:
            locks.append(
                {
                    **lock,
                    "duid": device["duid"],
                    "device_name": device["name"],
                    "device_model": device["model"],
                    # Momentaufnahme fuer den Notfall -- zur Laufzeit holen die
                    # Entities die rotierenden Geheimnisse frisch ueber
                    # client.get_device_credentials().
                    "data_encode_key": device.get("data_encode_key"),
                    "out_auth_code": device.get("out_auth_code"),
                }
            )

    entry.runtime_data = BalterRuntimeData(
        client=client, p2p_client_id=p2p_client_id, devices=devices, locks=locks
    )
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> None:
    """Reload when the signalling id or PIN was changed in the options."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

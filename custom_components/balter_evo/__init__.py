"""The Balter EVO (Quvii Cloud) integration."""
from __future__ import annotations

from dataclasses import dataclass, field
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterAuthError, BalterCloudClient
from .const import CONF_CLIENT_ID

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LOCK]


@dataclass
class BalterRuntimeData:
    """Runtime state shared with the platforms via ``entry.runtime_data``."""

    client: BalterCloudClient
    locks: list[dict] = field(default_factory=list)


type BalterConfigEntry = ConfigEntry[BalterRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Set up Balter EVO from a config entry."""
    session = aiohttp_client.async_get_clientsession(hass)
    client = BalterCloudClient(
        session,
        entry.data[CONF_EMAIL],
        entry.data[CONF_PASSWORD],
        client_id=entry.data.get(CONF_CLIENT_ID),
    )

    try:
        await client.login()
        devices = await client.get_device_list()
    except BalterAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except BalterApiError as err:
        raise ConfigEntryNotReady(str(err)) from err

    locks: list[dict] = []
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
                }
            )

    if not locks:
        raise ConfigEntryNotReady("No door locks reported by the account yet")

    entry.runtime_data = BalterRuntimeData(client=client, locks=locks)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: BalterConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

"""The Balter EVO (Quvii Cloud) integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterCloudClient
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BUTTON]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Balter EVO from a config entry."""
    session = aiohttp_client.async_get_clientsession(hass)
    client = BalterCloudClient(
        session,
        entry.data[CONF_EMAIL],
        entry.data[CONF_PASSWORD],
        client_id=entry.data.get("client_id"),
    )

    try:
        await client.login()
        devices = await client.get_device_list()
    except BalterApiError as err:
        _LOGGER.error("Balter EVO login/setup failed: %s", err)
        return False

    locks: list[dict] = []
    for device in devices:
        try:
            device_locks = await client.get_subdev_list(device["duid"])
        except BalterApiError as err:
            _LOGGER.warning(
                "Could not read locks for device %s: %s", device["duid"], err
            )
            continue
        for lock in device_locks:
            locks.append({**lock, "duid": device["duid"], "device_name": device["name"]})

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "locks": locks,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok

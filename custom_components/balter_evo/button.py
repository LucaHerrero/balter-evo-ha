"""Button entities that trigger the door-open command for each discovered lock."""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import BalterApiError, BalterCloudClient
from .const import CONF_DOOR_PIN, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client: BalterCloudClient = data["client"]
    locks: list[dict] = data["locks"]

    entities = [
        BalterDoorButton(client, entry, lock, entry.data[CONF_DOOR_PIN])
        for lock in locks
    ]
    async_add_entities(entities)


class BalterDoorButton(ButtonEntity):
    """A single door-release relay, exposed as a momentary button."""

    _attr_has_entity_name = True

    def __init__(
        self,
        client: BalterCloudClient,
        entry: ConfigEntry,
        lock: dict,
        pin: str,
    ) -> None:
        self._client = client
        self._entry = entry
        self._lock = lock
        self._pin = pin
        self._attr_unique_id = f"{lock['duid']}_{lock['code']}"
        self._attr_name = lock["name"]
        self._attr_icon = "mdi:door-open"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock["duid"])},
            name=lock["device_name"],
            manufacturer="Balter / Homaxi",
        )

    async def async_press(self) -> None:
        """Fetch a fresh device password and send the unlock command."""
        await self._client.ensure_logged_in()
        try:
            devices = await self._client.get_device_list()
        except BalterApiError as err:
            _LOGGER.error("Could not refresh device list before unlock: %s", err)
            raise

        dynamic_password = next(
            (d["dynamic_password"] for d in devices if d["duid"] == self._lock["duid"]),
            None,
        )
        if not dynamic_password:
            raise BalterApiError(
                f"Device {self._lock['duid']} no longer listed on the account"
            )

        await self._client.open_lock(
            dynamic_password,
            self._lock["door"],
            self._lock["locknumber"],
            self._pin,
        )

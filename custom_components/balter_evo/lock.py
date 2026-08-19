"""Lock entities for each Balter EVO door-release relay.

Uses the reverse-engineered UDP/KCP P2P protocol for direct, reliable hardware unlock.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_call_later

from . import BalterConfigEntry
from .api import BalterApiError, BalterCloudClient
from .const import CONF_DOOR_PIN, DOMAIN, RELOCK_DELAY
from .p2p import async_p2p_open_door

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one lock entity per discovered door-release relay."""
    data = entry.runtime_data
    pin = entry.data[CONF_DOOR_PIN]
    async_add_entities(BalterDoorLock(data.client, lock, pin) for lock in data.locks)


class BalterDoorLock(LockEntity):
    """A single door-release relay, exposed as an optimistic (momentary) lock."""

    _attr_has_entity_name = True
    _attr_assumed_state = True
    _attr_icon = "mdi:door"

    def __init__(self, client: BalterCloudClient, lock: dict, pin: str) -> None:
        self._client = client
        self._lock = lock
        self._pin = pin
        self._attr_is_locked = True
        self._relock_unsub: Any = None
        self._attr_unique_id = f"{lock['duid']}_{lock['code']}"
        self._attr_name = f"Türstation {lock['door']} Schloss {lock['locknumber']}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, lock["duid"])},
            name=lock["device_name"],
            manufacturer="Balter / Homaxi",
            model=lock.get("device_model"),
        )

    async def async_unlock(self, **kwargs: Any) -> None:
        """Fetch a fresh device password and trigger the door-release relay via P2P."""
        try:
            dynamic_password = await self._client.get_dynamic_password(self._lock["duid"])
            success = await async_p2p_open_door(
                self.hass,
                self._lock["duid"],
                dynamic_password,
                self._pin,
                door=self._lock["door"],
                locknumber=self._lock["locknumber"],
            )
            if not success:
                raise HomeAssistantError("Keine Bestätigung vom Türöffner empfangen")
        except Exception as err:
            raise HomeAssistantError(f"Türöffnen fehlgeschlagen: {err}") from err

        self._attr_is_locked = False
        self.async_write_ha_state()
        self._schedule_relock()

    async def async_lock(self, **kwargs: Any) -> None:
        """Reset the shown state to locked (the relay re-locks on its own)."""
        self._cancel_relock()
        self._attr_is_locked = True
        self.async_write_ha_state()

    @callback
    def _schedule_relock(self) -> None:
        self._cancel_relock()
        self._relock_unsub = async_call_later(self.hass, RELOCK_DELAY, self._relock)

    @callback
    def _relock(self, _now: Any) -> None:
        self._relock_unsub = None
        self._attr_is_locked = True
        self.async_write_ha_state()

    @callback
    def _cancel_relock(self) -> None:
        if self._relock_unsub is not None:
            self._relock_unsub()
            self._relock_unsub = None

    async def async_will_remove_from_hass(self) -> None:
        self._cancel_relock()

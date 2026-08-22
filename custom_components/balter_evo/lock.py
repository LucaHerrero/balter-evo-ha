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
from .const import CONF_DOOR_PIN, DOMAIN, OEM_ID, RELOCK_DELAY
from .p2p import async_p2p_open_door

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one lock entity per discovered door-release relay."""
    data = entry.runtime_data
    pin = entry.data.get(CONF_DOOR_PIN, "")
    async_add_entities(
        BalterDoorLock(data.client, lock, pin, data.p2p_client_id) for lock in data.locks
    )


class BalterDoorLock(LockEntity):
    """A single door-release relay, exposed as an optimistic (momentary) lock."""

    _attr_has_entity_name = True
    _attr_assumed_state = True
    _attr_icon = "mdi:door"

    def __init__(
        self, client: BalterCloudClient, lock: dict, pin: str, client_id: str
    ) -> None:
        self._client = client
        self._lock = lock
        self._pin = pin
        self._client_id = client_id
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
        """Trigger the door-release relay via P2P."""
        duid = self._lock["duid"]
        _LOGGER.info("Door unlock requested for %s (%s)", self.name, duid)
        try:
            # dynamic_password und data_encode_key rotieren woechentlich -- immer
            # frisch holen (gecacht), nie die Werte vom Setup-Zeitpunkt benutzen.
            creds = await self._client.get_device_credentials(duid)

            # Ohne konfigurierte PIN den out-auth-code der Geraeteliste nehmen:
            # verifiziert gilt out_auth_code == SHA256(<Tuer-PIN>), das Geraet
            # bekommt in beiden Faellen exakt denselben Hash.
            pin_sha256 = None if self._pin else (creds.get("out_auth_code") or None)

            # The OPENDOOR payload carries the raw 1-based subdev indices, exactly as the
            # official app sends them (verified against live_real.pcap: door=1, lock=1).
            door_idx = int(self._lock.get("door", 1))
            lock_idx = int(self._lock.get("locknumber", 1))

            success = await async_p2p_open_door(
                self.hass,
                duid,
                creds.get("dynamic_password") or "",
                self._pin,
                client_id=self._client_id,
                oem=OEM_ID.replace(",", ""),
                door=door_idx,
                locknumber=lock_idx,
                data_encode_key=creds.get("data_encode_key")
                or self._lock.get("data_encode_key"),
                pin_sha256=pin_sha256,
            )
            if not success:
                raise HomeAssistantError(
                    "Der Türöffner hat den Befehl nicht quittiert. Die Tür wurde "
                    "vermutlich nicht geöffnet."
                )
        except HomeAssistantError:
            raise
        except Exception as err:
            _LOGGER.error("P2P door unlock failed: %s", err)
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

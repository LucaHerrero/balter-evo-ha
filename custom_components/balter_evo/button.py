"""Button platform: start the door station's live view on demand.

The camera deliberately does not stream on its own -- the station serves only one
P2P session, and a permanently open stream would block the doorbell and the phone
app. This button is the explicit "I want to look now" trigger: it starts a single
bounded session, after which the station is free again.
"""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import BalterConfigEntry, BalterRuntimeData
from .const import DOMAIN, STREAM_DURATION

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Create one live-view button per door station."""
    data = entry.runtime_data
    async_add_entities(
        BalterLiveViewButton(data, device) for device in data.devices
    )


class BalterLiveViewButton(ButtonEntity):
    """Starts a bounded live session on one door station."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:video"

    def __init__(self, data: BalterRuntimeData, device: dict) -> None:
        """Initialise the live-view button of one door station."""
        self._data = data
        self._duid = device["duid"]
        self._attr_unique_id = f"{self._duid}_live_view"
        self._attr_name = f"Live-Bild ({STREAM_DURATION:.0f} s)"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._duid)},
            name=device.get("name", "Balter EVO"),
            manufacturer="Balter / Homaxi",
            model=device.get("model", "EVO"),
        )

    async def async_press(self) -> None:
        """Start the live session on the camera entity of the same station."""
        camera = self._data.cameras.get(self._duid)
        if camera is None:
            # Die Kamera-Plattform wird parallel eingerichtet; bis sie da ist,
            # gibt es nichts zu starten.
            raise HomeAssistantError(
                "Die Kamera dieser Türstation ist noch nicht bereit. "
                "Bitte kurz warten und erneut drücken."
            )
        if camera.is_streaming:
            _LOGGER.debug("Live view for %s is already running", self._duid)
            return
        _LOGGER.info(
            "Live view requested for %s (%.0fs)", self._duid, STREAM_DURATION
        )
        await camera.async_turn_on()

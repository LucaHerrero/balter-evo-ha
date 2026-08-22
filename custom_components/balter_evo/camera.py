"""Camera platform for Balter EVO video door stations.

Designed for on-demand snapshot access with zero continuous background streaming.
This ensures the door intercom is NEVER blocked for other residents or incoming rings.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import voluptuous as vol

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.core import HomeAssistant, SupportsResponse
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv, entity_platform
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import BalterConfigEntry
from .api import BalterCloudClient
from .const import DOMAIN, OEM_ID, SERVICE_RECORD_CLIP
from .p2p import async_p2p_get_snapshot, async_p2p_record_clip

_LOGGER = logging.getLogger(__name__)

# Minimum cache time in seconds to prevent flooding the door station on rapid dashboard refreshes
SNAPSHOT_CACHE_TTL = 15.0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Balter EVO camera entities."""
    data = entry.runtime_data
    entities = []

    for device in data.devices:
        entities.append(BalterDoorbellCamera(hass, data.client, device))

    async_add_entities(entities)

    platform = entity_platform.async_get_current_platform()
    platform.async_register_entity_service(
        SERVICE_RECORD_CLIP,
        {
            vol.Required("filename"): cv.string,
            vol.Optional("seconds", default=5.0): vol.All(
                vol.Coerce(float), vol.Range(min=1.0, max=30.0)
            ),
        },
        "async_record_clip",
        supports_response=SupportsResponse.OPTIONAL,
    )


class BalterDoorbellCamera(Camera):
    """Camera entity for a Balter EVO video door station."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:doorbell-video"
    _attr_supported_features = CameraEntityFeature.ON_OFF
    _attr_should_poll = False

    def __init__(
        self,
        hass: HomeAssistant,
        client: BalterCloudClient,
        device: dict[str, Any],
    ) -> None:
        """Initialize the doorbell camera entity."""
        super().__init__()
        self.hass = hass
        self._client = client
        self._device = device
        self._duid = device["duid"]
        self._attr_unique_id = f"{self._duid}_camera"
        self._attr_name = f"{device.get('name', 'Türstation')} Kamera"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._duid)},
            name=device.get("name", "Balter EVO"),
            manufacturer="Balter / Homaxi",
            model=device.get("model", "EVO 2"),
        )
        self._last_image: bytes | None = None
        self._last_image_time: float = 0
        self._lock = asyncio.Lock()

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return a still image on demand.
        
        Uses an in-memory cache to prevent continuous channel occupation.
        If a new frame is needed, it fetches it transiently and releases the session immediately.
        """
        now = time.time()
        # Serve cached image if within TTL to protect intercom availability
        if self._last_image and (now - self._last_image_time < SNAPSHOT_CACHE_TTL):
            return self._last_image

        async with self._lock:
            # Double-check cache after acquiring lock
            if self._last_image and (time.time() - self._last_image_time < SNAPSHOT_CACHE_TTL):
                return self._last_image

            try:
                # Beide Geheimnisse rotieren woechentlich -> immer frisch holen.
                creds = await self._client.get_device_credentials(self._duid)

                image_bytes = await async_p2p_get_snapshot(
                    self.hass,
                    self._duid,
                    creds.get("dynamic_password") or "",
                    data_encode_key=creds.get("data_encode_key")
                    or self._device.get("data_encode_key"),
                    oem=OEM_ID.replace(",", ""),
                )
                if image_bytes:
                    self._last_image = image_bytes
                    self._last_image_time = time.time()
                    return image_bytes
            except Exception as err:
                _LOGGER.warning("Could not fetch P2P snapshot for %s: %s", self._duid, err)

        return self._last_image

    async def async_record_clip(self, seconds: float, filename: str) -> dict[str, Any]:
        """Record a short MP4 clip and write it to ``filename``.

        Backs the ``balter_evo.record_clip`` entity service. The door station
        starts sending video about two seconds after the login, so the recorder
        captures a longer window and trims the clip to the requested length.
        """
        if not self.hass.config.is_allowed_path(filename):
            raise HomeAssistantError(
                f"Pfad {filename} ist nicht freigegeben (siehe allowlist_external_dirs)"
            )

        async with self._lock:
            creds = await self._client.get_device_credentials(self._duid)
            clip = await async_p2p_record_clip(
                self.hass,
                self._duid,
                creds.get("dynamic_password") or "",
                data_encode_key=creds.get("data_encode_key")
                or self._device.get("data_encode_key"),
                oem=OEM_ID.replace(",", ""),
                seconds=seconds,
            )

        if not clip:
            raise HomeAssistantError(
                "Kein Videoclip erhalten -- Handshake gescheitert oder ffmpeg fehlt"
            )

        def _write() -> None:
            with open(filename, "wb") as fh:
                fh.write(clip)

        await self.hass.async_add_executor_job(_write)
        _LOGGER.info("Balter EVO: wrote %.1fs clip (%d bytes) to %s",
                     seconds, len(clip), filename)
        return {"filename": filename, "size": len(clip), "seconds": seconds}

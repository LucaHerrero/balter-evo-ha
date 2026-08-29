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
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_platform
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import BalterConfigEntry
from .api import BalterCloudClient
from .const import (
    DOMAIN,
    OEM_ID_COMPACT,
    SERVICE_RECORD_CLIP,
    SNAPSHOT_CACHE_TTL,
    STREAM_DURATION,
    STREAM_STOP_TIMEOUT,
)
from .p2p import (
    async_p2p_get_snapshot,
    async_p2p_record_clip,
    async_p2p_stream_video,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Balter EVO camera entities."""
    data = entry.runtime_data
    async_add_entities(
        BalterDoorbellCamera(data.client, device, data.p2p_client_id, data.warm_idle)
        for device in data.devices
    )

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
    # Poll-Takt der Standard-MJPEG-Schleife: waehrend eines Live-Streams liest sie
    # so ~11x/s das neueste JPEG -> fluessiges Video statt Diashow.
    _attr_frame_interval = 0.09

    def __init__(
        self,
        client: BalterCloudClient,
        device: dict[str, Any],
        client_id: str,
        warm_idle: float,
    ) -> None:
        """Initialize the doorbell camera entity."""
        super().__init__()
        self._client = client
        self._device = device
        self._client_id = client_id
        self._warm_idle = warm_idle
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
        # Live-Stream-Zustand
        self._streaming = False
        self._stop_stream = False
        self._live_jpeg: bytes | None = None
        self._stream_task: asyncio.Task | None = None

    @property
    def is_on(self) -> bool:
        """Camera 'on' == a live stream is currently running."""
        return self._streaming

    @property
    def is_streaming(self) -> bool:
        """Return True while a live stream is running."""
        return self._streaming

    def _on_jpeg(self, jpg: bytes) -> None:
        """Handle one decoded live frame (called from the executor thread)."""
        self._live_jpeg = jpg
        self._last_image = jpg
        self._last_image_time = time.time()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Start a live stream (auto-stops after STREAM_DURATION seconds)."""
        if self._streaming:
            return
        self._stop_stream = False
        self._streaming = True
        self.async_write_ha_state()
        # Hintergrundaufgabe: Home Assistant wartet beim Start nicht darauf und
        # raeumt sie beim Herunterfahren mit ab.
        self._stream_task = self.hass.async_create_background_task(
            self._run_stream(), name=f"{DOMAIN}_stream_{self._duid}"
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Stop the running live stream."""
        self._stop_stream = True

    async def _run_stream(self) -> None:
        """Drive one bounded live stream and release the P2P slot afterwards."""
        _LOGGER.info("Starting live stream for %s", self._duid)
        try:
            creds = await self._client.get_device_credentials(self._duid)
            await async_p2p_stream_video(
                self.hass,
                self._duid,
                creds.get("dynamic_password") or "",
                data_encode_key=creds.get("data_encode_key")
                or self._device.get("data_encode_key"),
                client_id=self._client_id,
                oem=OEM_ID_COMPACT,
                duration=STREAM_DURATION,
                on_jpeg=self._on_jpeg,
                should_stop=lambda: self._stop_stream,
                warm_idle=self._warm_idle,
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Live stream for %s failed: %s", self._duid, err)
        finally:
            self._streaming = False
            self._stop_stream = False
            self._live_jpeg = None
            self.async_write_ha_state()

    async def handle_async_mjpeg_stream(self, request: Any) -> Any:
        """Serve the live MJPEG feed, auto-starting the stream when a viewer opens it."""
        if not self._streaming:
            await self.async_turn_on()
        return await super().handle_async_mjpeg_stream(request)

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the current frame.

        While a live stream runs, serve its newest decoded frame (this is what
        makes the MJPEG feed move). Otherwise fetch a single cached snapshot so
        the door intercom is never blocked for other residents.
        """
        if self._streaming and self._live_jpeg:
            return self._live_jpeg

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
                    client_id=self._client_id,
                    oem=OEM_ID_COMPACT,
                    warm_idle=self._warm_idle,
                )
                if image_bytes:
                    self._last_image = image_bytes
                    self._last_image_time = time.time()
                    return image_bytes
            except Exception as err:  # noqa: BLE001
                _LOGGER.warning("Could not fetch P2P snapshot for %s: %s", self._duid, err)

        return self._last_image

    async def async_will_remove_from_hass(self) -> None:
        """Stop any running stream when the entity goes away."""
        self._stop_stream = True
        task = self._stream_task
        self._stream_task = None
        if task is None or task.done():
            return
        # Der Runner prueft should_stop und gibt den P2P-Slot selbst frei; nur
        # falls er das nicht rechtzeitig schafft, hart abbrechen. asyncio.wait
        # statt await: es verschluckt kein CancelledError des eigenen Tasks.
        done, _ = await asyncio.wait({task}, timeout=STREAM_STOP_TIMEOUT)
        if not done:
            _LOGGER.warning(
                "Live stream for %s did not stop in time -- cancelling it", self._duid
            )
            task.cancel()

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
                client_id=self._client_id,
                oem=OEM_ID_COMPACT,
                seconds=seconds,
                warm_idle=self._warm_idle,
            )

        if not clip:
            raise HomeAssistantError(
                "Kein Videoclip erhalten -- Handshake gescheitert oder ffmpeg fehlt"
            )

        def _write() -> None:
            with open(filename, "wb") as fh:
                fh.write(clip)

        await self.hass.async_add_executor_job(_write)
        _LOGGER.info("Wrote %.1fs clip (%d bytes) to %s",
                     seconds, len(clip), filename)
        return {"filename": filename, "size": len(clip), "seconds": seconds}

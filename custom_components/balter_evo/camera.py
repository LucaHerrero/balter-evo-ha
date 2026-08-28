"""Camera platform for Balter EVO video door stations.

Designed for on-demand snapshot access with zero continuous background streaming.
This ensures the door intercom is NEVER blocked for other residents or incoming rings.
"""
from __future__ import annotations

import asyncio
import logging
import socket
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

from . import BalterConfigEntry, BalterRuntimeData
from .api import BalterCloudClient
from .const import (
    DOMAIN,
    OEM_ID_COMPACT,
    SERVICE_RECORD_CLIP,
    SNAPSHOT_CACHE_TTL,
    STREAM_DURATION,
    STREAM_STOP_TIMEOUT,
    STREAM_TS_HOST,
    STREAM_TS_INPUT_OPTIONS,
)
from .p2p import (
    async_p2p_get_snapshot,
    async_p2p_record_clip,
    async_p2p_stream_video,
)

_LOGGER = logging.getLogger(__name__)


def _free_udp_port() -> int:
    """Pick a currently free loopback UDP port for the MPEG-TS handover.

    The port is released again right away -- ffmpeg sends to it and the stream
    component binds it. A fixed port would clash as soon as a second door
    station streams.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((STREAM_TS_HOST, 0))
        return int(probe.getsockname()[1])


async def async_setup_entry(
    hass: HomeAssistant,
    entry: BalterConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up Balter EVO camera entities."""
    data = entry.runtime_data
    async_add_entities(
        BalterDoorbellCamera(data, device) for device in data.devices
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
    # STREAM: waehrend einer laufenden Sitzung liefert async_stream_source den
    # unveraenderten H.264-Strom an die stream-Integration. Ausserhalb gibt es
    # keine Quelle -- Home Assistant faellt dann auf Einzelbilder zurueck und
    # kann von sich aus KEINE P2P-Sitzung starten. Genau so muss es sein: die
    # Station bedient nur eine Sitzung, und wann die laeuft, entscheiden wir.
    _attr_supported_features = CameraEntityFeature.ON_OFF | CameraEntityFeature.STREAM
    _attr_should_poll = False
    # Poll-Takt der Standard-MJPEG-Schleife: waehrend eines Live-Streams liest sie
    # so ~11x/s das neueste JPEG -> fluessiges Video statt Diashow.
    _attr_frame_interval = 0.09

    def __init__(self, data: BalterRuntimeData, device: dict[str, Any]) -> None:
        """Initialize the doorbell camera entity."""
        super().__init__()
        self._data = data
        self._client: BalterCloudClient = data.client
        self._device = device
        self._client_id = data.p2p_client_id
        self._warm_idle = data.warm_idle
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
        # Loopback-Port des MPEG-TS-Ausgangs der laufenden Sitzung.
        self._ts_port: int | None = None

    @property
    def is_on(self) -> bool:
        """Camera 'on' == a live stream is currently running."""
        return self._streaming

    @property
    def is_streaming(self) -> bool:
        """Return True while a live stream is running."""
        return self._streaming

    async def async_added_to_hass(self) -> None:
        """Make this camera findable for the live-view button of the same station."""
        self._data.cameras[self._duid] = self

    async def async_stream_source(self) -> str | None:
        """Return the live H.264 source, or None while no session is running.

        Returning None outside a session is what keeps the door station usable:
        the stream component reopens and keeps sources alive on its own, and an
        always-available URL would let it occupy the station's single P2P slot
        indefinitely -- shutting out the doorbell and the phone app.
        """
        if not self._streaming or self._ts_port is None:
            return None
        return f"udp://{STREAM_TS_HOST}:{self._ts_port}?{STREAM_TS_INPUT_OPTIONS}"

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
        self._ts_port = _free_udp_port()
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
                ts_url=(
                    f"udp://{STREAM_TS_HOST}:{self._ts_port}?pkt_size=1316"
                    if self._ts_port
                    else None
                ),
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning("Live stream for %s failed: %s", self._duid, err)
        finally:
            self._streaming = False
            self._stop_stream = False
            self._live_jpeg = None
            self._ts_port = None
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
        self._data.cameras.pop(self._duid, None)
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

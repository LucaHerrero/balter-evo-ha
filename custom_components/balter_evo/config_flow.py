"""Config flow for Balter EVO (Quvii Cloud)."""
from __future__ import annotations

import logging
import re
import secrets
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterAuthError, BalterCloudClient
from .const import (
    CONF_CLIENT_ID,
    CONF_DOOR_PIN,
    CONF_SIGNALLING_ID,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

HEX16 = re.compile(r"^[0-9a-f]{16}$")

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_DOOR_PIN, default=""): str,
        vol.Optional(CONF_SIGNALLING_ID, default=""): str,
    }
)


def _normalise_signalling_id(value: str) -> str:
    """Accept the app client id in any casing/spacing; '' means 'none given'."""
    return (value or "").strip().lower()


class BalterEvoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Balter EVO."""

    VERSION = 2

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            signalling_id = _normalise_signalling_id(user_input.get(CONF_SIGNALLING_ID, ""))
            if signalling_id and not HEX16.match(signalling_id):
                errors[CONF_SIGNALLING_ID] = "invalid_signalling_id"
            else:
                session = aiohttp_client.async_get_clientsession(self.hass)
                # Eigene 16-Hex-Identitaet, im selben Format wie die App sie nutzt.
                # Sie gilt fuer Cloud-Login und den P2P-LOGIN am Geraet; nur die
                # MQTT-Signalisierung braucht eine registrierte ID.
                client_id = secrets.token_hex(8)
                client = BalterCloudClient(
                    session,
                    user_input[CONF_EMAIL],
                    user_input[CONF_PASSWORD],
                    client_id=signalling_id or client_id,
                )
                try:
                    await client.login()
                except BalterAuthError:
                    errors["base"] = "invalid_auth"
                except BalterApiError as err:
                    _LOGGER.error("Balter EVO connection error: %s", err)
                    errors["base"] = "cannot_connect"
                else:
                    await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
                    self._abort_if_unique_id_configured()
                    data = {
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_DOOR_PIN: user_input.get(CONF_DOOR_PIN, ""),
                        CONF_CLIENT_ID: client_id,
                        CONF_SIGNALLING_ID: signalling_id,
                    }
                    return self.async_create_entry(title=user_input[CONF_EMAIL], data=data)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        return BalterEvoOptionsFlow()


class BalterEvoOptionsFlow(config_entries.OptionsFlow):
    """Allow adding/changing the signalling id and door PIN after setup."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        entry = self.config_entry
        errors: dict[str, str] = {}

        if user_input is not None:
            signalling_id = _normalise_signalling_id(user_input.get(CONF_SIGNALLING_ID, ""))
            if signalling_id and not HEX16.match(signalling_id):
                errors[CONF_SIGNALLING_ID] = "invalid_signalling_id"
            else:
                self.hass.config_entries.async_update_entry(
                    entry,
                    data={
                        **entry.data,
                        CONF_SIGNALLING_ID: signalling_id,
                        CONF_DOOR_PIN: user_input.get(CONF_DOOR_PIN, ""),
                    },
                )
                return self.async_create_entry(title="", data={})

        current = entry.data
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_SIGNALLING_ID,
                    default=current.get(CONF_SIGNALLING_ID, ""),
                ): str,
                vol.Optional(
                    CONF_DOOR_PIN, default=current.get(CONF_DOOR_PIN, "")
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

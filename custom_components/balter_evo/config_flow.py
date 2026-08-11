"""Config flow for Balter EVO (Quvii Cloud)."""
from __future__ import annotations

import logging
import secrets
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterAuthError, BalterCloudClient
from .const import APP_ID, CONF_CLIENT_ID, CONF_DOOR_PIN, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_DOOR_PIN): str,
    }
)


class BalterEvoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Balter EVO."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            session = aiohttp_client.async_get_clientsession(self.hass)
            client_id = f"003-{APP_ID}-{secrets.token_hex(8)}"
            client = BalterCloudClient(
                session,
                user_input[CONF_EMAIL],
                user_input[CONF_PASSWORD],
                client_id=client_id,
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
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data={**user_input, CONF_CLIENT_ID: client_id},
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

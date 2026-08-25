"""Config flow for Balter EVO (Quvii Cloud)."""
from __future__ import annotations

import logging
import secrets
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import ConfigFlowResult
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.helpers import aiohttp_client

from .api import BalterApiError, BalterAuthError, BalterCloudClient
from .const import CONF_CLIENT_ID, CONF_DOOR_PIN, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_EMAIL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)

STEP_REAUTH_SCHEMA = vol.Schema({vol.Required(CONF_PASSWORD): str})


class BalterEvoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Balter EVO."""

    VERSION = 2

    async def _async_try_login(self, email: str, password: str, client_id: str) -> str | None:
        """Verify credentials; return an error key, or None on success."""
        client = BalterCloudClient(
            aiohttp_client.async_get_clientsession(self.hass),
            email,
            password,
            client_id=client_id,
        )
        try:
            await client.login()
        except BalterAuthError:
            return "invalid_auth"
        except BalterApiError as err:
            _LOGGER.error("Cloud connection error: %s", err)
            return "cannot_connect"
        return None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            # Eigene 16-Hex-Identitaet; die MQTT-Credentials dafuer leitet die
            # Integration selbst ab (qv_kdf) -- keine Registrierung noetig.
            client_id = secrets.token_hex(8)
            error = await self._async_try_login(
                user_input[CONF_EMAIL], user_input[CONF_PASSWORD], client_id
            )
            if error:
                errors["base"] = error
            else:
                await self.async_set_unique_id(user_input[CONF_EMAIL].lower())
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=user_input[CONF_EMAIL],
                    data={
                        CONF_EMAIL: user_input[CONF_EMAIL],
                        CONF_PASSWORD: user_input[CONF_PASSWORD],
                        CONF_DOOR_PIN: "",
                        CONF_CLIENT_ID: client_id,
                    },
                )

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_SCHEMA, errors=errors
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication after the cloud rejected the credentials."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the password again and update the existing entry."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            error = await self._async_try_login(
                entry.data[CONF_EMAIL],
                user_input[CONF_PASSWORD],
                entry.data.get(CONF_CLIENT_ID) or secrets.token_hex(8),
            )
            if error:
                errors["base"] = error
            else:
                return self.async_update_reload_and_abort(
                    entry, data_updates={CONF_PASSWORD: user_input[CONF_PASSWORD]}
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=STEP_REAUTH_SCHEMA,
            description_placeholders={"email": entry.data[CONF_EMAIL]},
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Return the options flow handler."""
        return BalterEvoOptionsFlow()


class BalterEvoOptionsFlow(config_entries.OptionsFlow):
    """Allow changing the door PIN after setup."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the door PIN."""
        entry = self.config_entry

        if user_input is not None:
            self.hass.config_entries.async_update_entry(
                entry,
                data={**entry.data, CONF_DOOR_PIN: user_input.get(CONF_DOOR_PIN, "")},
            )
            return self.async_create_entry(title="", data={})

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_DOOR_PIN, default=entry.data.get(CONF_DOOR_PIN, "")
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)

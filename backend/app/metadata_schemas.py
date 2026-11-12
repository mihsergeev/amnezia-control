"""Display labels never participate in node commands or profile identifiers."""

import unicodedata
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class ClientLabels(BaseModel):
    group_name: str = Field(default="", max_length=128)
    device_name: str = Field(default="", max_length=128)

    @field_validator("group_name", "device_name", mode="before")
    @classmethod
    def display_label(cls, value):
        if value is None:
            return ""
        if isinstance(value, str):
            if any(unicodedata.category(char).startswith("C") for char in value):
                raise ValueError("Control characters are not allowed in display labels")
            return value.strip()
        return value


class ClientMetadataRequest(ClientLabels):
    protocol: Literal["awg", "awg3", "awglegacy", "openvpn", "xray", "wireguard", "openvpn-native"]
    client_id: str = Field(min_length=1, max_length=128)


def metadata_identity(protocol: str, client_id: str) -> str:
    """Use the same UUID aliases as the existing Xray bulk journal."""
    if protocol == "xray" and isinstance(client_id, str):
        try:
            return str(UUID(client_id))
        except ValueError:
            pass
    return client_id


class BulkClientMetadataRequest(BaseModel):
    protocol: Literal["awg", "awg3", "awglegacy", "openvpn", "xray", "wireguard", "openvpn-native"]
    client_ids: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(min_length=1, max_length=100)
    group_name: str = Field(max_length=128)

    @field_validator("client_ids")
    @classmethod
    def unique_identities(cls, values, info):
        identities = [metadata_identity(info.data.get("protocol", ""), value) for value in values]
        if len(set(identities)) != len(values):
            raise ValueError("Client identifiers must be unique")
        return values

    @field_validator("group_name", mode="before")
    @classmethod
    def display_group(cls, value):
        # A group is required here; only the single-client API accepts null.
        return ClientLabels.display_label(value) if value is not None else value

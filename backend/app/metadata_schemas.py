"""Display labels never participate in node commands or profile identifiers."""

import unicodedata
from typing import Literal

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

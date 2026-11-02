"""Native protocol requests; legacy Amnezia response contracts remain unchanged."""

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class NativeDeployRequest(BaseModel):
    port: int | None = Field(default=None, ge=1, le=65535)
    transport: Literal["udp", "tcp"] = "udp"


class NativeCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=512)
    expires_at: datetime | None = None
    dns: str = ""

    @field_validator("dns")
    @classmethod
    def valid_dns(cls, value: str) -> str:
        if not value.strip():
            return ""
        values = [str(ipaddress.ip_address(part.strip())) for part in value.split(",")]
        return ", ".join(values)


class NativeClientRequest(BaseModel):
    public_key: str | None = None
    client_id: str | None = None

    @model_validator(mode="after")
    def one_identifier(self):
        if bool(self.public_key) == bool(self.client_id):
            raise ValueError("Exactly one client identifier is required")
        return self


class NativeNoteRequest(NativeClientRequest):
    note: str = Field(default="", max_length=512)


class NativeConfigResponse(BaseModel):
    config: str
    name: str
    filename: str
    format: Literal["wireguard", "openvpn"]


class NativeCreateResponse(NativeConfigResponse):
    client: dict

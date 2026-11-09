from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

MAX_ISSUE = 100
MAX_EXPORT = 1000
MAX_REVOKE = 100

IssueProtocol = Literal["awg3", "wireguard", "xray"]
ExportProtocol = Literal["awg3", "wireguard", "xray", "awg", "awglegacy", "openvpn-native", "openvpn"]


def _confirmed(value: object) -> bool:
    if value is not True:
        raise ValueError("Подтвердите операцию")
    return True


Confirmed = Annotated[Literal[True], BeforeValidator(_confirmed)]


class IssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID
    prefix: str = Field(min_length=1, max_length=124)
    count: int = Field(ge=1, le=MAX_ISSUE, strict=True)
    confirmed: Confirmed

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, prefix: str) -> str:
        prefix = prefix.strip()
        if not prefix or any(not char.isprintable() for char in prefix):
            raise ValueError("Префикс должен содержать печатные символы")
        return prefix

    def names(self) -> list[str]:
        return [f"{self.prefix}-{index:03}" for index in range(1, self.count + 1)]


class PendingIssue(BaseModel):
    request_id: UUID
    prefix: str
    count: int
    client_ids: list[str]


class IssueItem(BaseModel):
    client_id: str
    name: str


class IssueResult(BaseModel):
    items: list[IssueItem]
    cancelled: int = 0


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_ids: list[str] = Field(min_length=1, max_length=MAX_EXPORT)

    @field_validator("client_ids")
    @classmethod
    def validate_ids(cls, ids: list[str]) -> list[str]:
        if any(not 1 <= len(item) <= 64 or not item.isprintable() for item in ids):
            raise ValueError("Недопустимый идентификатор клиента")
        return list(dict.fromkeys(ids))


class RevokeRequest(ExportRequest):
    client_ids: list[str] = Field(min_length=1, max_length=MAX_REVOKE)
    confirmed: Confirmed

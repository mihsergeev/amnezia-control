from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from app import audit, remembered_sessions, stepup, update_worker
from app.api.auth import AuthRoute
from app.deps import CurrentUser, SessionDep
from app.schemas import ReleaseCheckOut

router = APIRouter(prefix="/updates", tags=["system"], route_class=AuthRoute)


class InstallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: update_worker.InstallVersion
    password: str = Field(min_length=1, max_length=128)
    otp: str | None = Field(default=None, pattern=r"^[0-9]{6}$")


class InstallationStatus(BaseModel):
    enabled: bool = False
    phase: update_worker.InstallationPhase = "idle"
    version: update_worker.InstallVersion | None = None
    error: str | None = None

    @classmethod
    def from_worker(cls, worker: update_worker.WorkerStatus | None) -> "InstallationStatus":
        if worker is None:
            return cls()
        return cls(enabled=True, phase=worker.phase, version=worker.version, error=worker.public_error)


def _require_https_browser(request: Request) -> None:
    if not remembered_sessions.valid_browser_request(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "browser_request_required")
    # The browser sets Origin before TLS terminates at the edge. Nginx forwards
    # Host without its port and reports the scheme of the internal HTTP hop.
    try:
        origin = urlsplit(request.headers.get("origin", ""))
        if (
            origin.scheme == "https"
            and origin.hostname is not None
            and origin.hostname == request.url.hostname
            and origin.username is None
            and origin.password is None
            and not (origin.path or origin.query or origin.fragment)
        ):
            return
    except ValueError:
        pass
    raise HTTPException(status.HTTP_403_FORBIDDEN, "https_required")


@router.get("", response_model=ReleaseCheckOut)
async def get_updates(request: Request, _: CurrentUser) -> ReleaseCheckOut:
    return await request.app.state.release_check.check()


@router.post("/check", response_model=ReleaseCheckOut)
async def check_updates(request: Request, _: CurrentUser) -> ReleaseCheckOut:
    return await request.app.state.release_check.check(manual=True)


@router.get("/installation", response_model=InstallationStatus)
async def installation_status(_: CurrentUser) -> InstallationStatus:
    return InstallationStatus.from_worker(await update_worker.get_status())


@router.post("/installation", response_model=InstallationStatus, status_code=status.HTTP_202_ACCEPTED)
async def install(body: InstallRequest, request: Request, user: CurrentUser, session: SessionDep) -> InstallationStatus:
    _require_https_browser(request)
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "2fa_setup_required")
    if body.otp is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "2fa_required")
    release = await request.app.state.release_check.check(manual=True)
    if release.status != "available" or release.stale or release.latest_version != f"v{body.version}":
        raise HTTPException(status.HTTP_409_CONFLICT, "release_unavailable")

    try:
        await stepup.verify(user, body.password, request, body.otp)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_403_FORBIDDEN:
            detail = "2fa_invalid" if exc.headers and exc.headers.get("X-Need-OTP") == "1" else "invalid_password"
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail) from exc
        raise

    # The worker may restart the API as soon as it accepts the request.
    await audit.record(session, user.username, "update_install_requested", body.version)
    outcome = await update_worker.request_install(body.version)
    if outcome is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "installer_unavailable")
    if not outcome.accepted:
        detail = "installation_busy" if outcome.busy else outcome.public_error or "installation_rejected"
        raise HTTPException(status.HTTP_409_CONFLICT, detail)
    return InstallationStatus.from_worker(outcome)

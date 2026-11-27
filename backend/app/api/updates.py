from fastapi import APIRouter, Request, Response

from app.deps import CurrentUser
from app.schemas import ReleaseCheckOut

router = APIRouter(prefix="/updates", tags=["system"])


@router.get("", response_model=ReleaseCheckOut)
async def get_updates(request: Request, response: Response, _: CurrentUser) -> ReleaseCheckOut:
    response.headers["Cache-Control"] = "no-store"
    return await request.app.state.release_check.check()


@router.post("/check", response_model=ReleaseCheckOut)
async def check_updates(request: Request, response: Response, _: CurrentUser) -> ReleaseCheckOut:
    response.headers["Cache-Control"] = "no-store"
    return await request.app.state.release_check.check(manual=True)

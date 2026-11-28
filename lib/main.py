import os
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Final
from contextlib import asynccontextmanager
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlencode

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from session_store import (
    create_session,
    delete_session,
    delete_session_row,
    hash_session_id,
    get_session,
    initialize_database,
    list_sessions,
    touch_session,
)

load_dotenv()


class App(StrEnum):
    """Entra app roles this service checks."""

    Reader = "App.Reader"
    Admin = "App.Admin"


# Entra directory that issues the tokens and hosts the login and logout endpoints.
TENANT_ID: Final = os.environ["ENTRA_TENANT_ID"]
# App registration this app authenticates as.
CLIENT_ID: Final = os.environ["ENTRA_CLIENT_ID"]
# Proves this app to Entra when exchanging the authorization code. Entra's secret, not ours.
CLIENT_SECRET: Final = os.environ["ENTRA_CLIENT_SECRET"]
# Signs the Starlette cookie that holds OAuth state and one-time banners.
# The session_id cookie is a separate unsigned lookup key stored in SQLite.
SESSION_SECRET: Final = os.environ["SESSION_SECRET"]

# Public origin of this app, with no trailing slash. Redirect URIs are derived from it.
APP_BASE_URL: Final = os.environ["APP_BASE_URL"].rstrip("/")
REDIRECT_URI: Final = f"{APP_BASE_URL}/auth/callback"
POST_LOGOUT_URI: Final = f"{APP_BASE_URL}/logged-out"
COOKIE_SECURE: Final = APP_BASE_URL.startswith("https://")

ENTRA_ENDPOINT: Final = f"https://login.microsoftonline.com/{TENANT_ID}"
ENTRA_LOGOUT_ENDPOINT: Final = f"{ENTRA_ENDPOINT}/oauth2/v2.0/logout"

# Uvicorn imports this module when the worker starts.
STARTED_AT: Final = time.monotonic()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create the session tables when the process starts."""
    initialize_database()
    yield


app = FastAPI(title="FastAPI SSO Lab", lifespan=lifespan)
STATIC_PATH: Final = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_PATH), name="static")
templates = Jinja2Templates(
    env=Environment(
        loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
        # .j2 is outside Jinja's default HTML autoescape suffixes.
        autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml", "j2")),
    )
)


def touch_session_cookie(session_id: str, response: Response) -> None:
    """Store the auto-generated session_id in a cookie."""

    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=3600,
    )


class RefreshSessionCookieMiddleware(BaseHTTPMiddleware):
    """Slide the session_id cookie after a route refreshed a live session."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        session_id = getattr(request.state, "refresh_session_id", None)
        if isinstance(session_id, str):
            touch_session_cookie(session_id, response)
        return response


# Signed session cookie. The refresh middleware is outermost so it sees the
# response the route returned.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="fastapi_sso_session",
    max_age=3600,
    same_site="lax",
    https_only=COOKIE_SECURE,
)
app.add_middleware(RefreshSessionCookieMiddleware)

# OIDC provider configuration
oauth = OAuth()

oauth.register(
    name="entra",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{ENTRA_ENDPOINT}/v2.0/.well-known/openid-configuration",
    client_kwargs={"scope": "openid profile email"},
)


async def get_current_user(request: Request) -> dict | None:
    """Return the user for the session cookie and extend that session."""
    session_id = request.cookies.get("session_id")

    if not session_id or not (user := get_session(session_id)):
        return None

    touch_session(session_id)
    request.state.refresh_session_id = session_id

    return user


async def require_current_user(
    request: Request, user: dict | None = Depends(get_current_user)
) -> dict:
    """Return the user for the session_id cookie, or raise 401."""

    if user:
        return user

    if not request.cookies.get("session_id"):
        raise HTTPException(status_code=401, detail="Not authenticated")

    raise HTTPException(status_code=401, detail="Session expired or invalid")


def require_role(required_role: App) -> Callable[..., Awaitable[dict]]:
    """Build a dependency that allows only users who have required_role."""

    async def role_checker(user: dict = Depends(require_current_user)) -> dict:
        """Reject the request when the signed-in user lacks required_role."""
        if required_role not in user["roles"]:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return role_checker


async def require_csrf(
    request: Request,
    csrf_token: str = Form(...),
) -> None:
    expected = request.session.get("csrf_token")

    if not expected or not secrets.compare_digest(csrf_token, expected):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def get_csrf_token(request: Request) -> str:
    if "csrf_token" not in request.session:
        request.session["csrf_token"] = secrets.token_urlsafe(32)

    return request.session["csrf_token"]


@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: dict | None = Depends(get_current_user)) -> HTMLResponse:
    """Show the signed-in user, or the sign-in page, plus a one-time banner."""

    if err_msg := request.session.pop("err_msg", None):
        banner, banner_role = err_msg, "alert"
    elif info_msg := request.session.pop("info_msg", None):
        banner, banner_role = info_msg, "info"
    else:
        banner = banner_role = None

    context = {
        "user": user,
        "banner": banner,
        "banner_role": banner_role,
        "admin_role": App.Admin,
        "csrf_token": get_csrf_token(request),
    }
    return templates.TemplateResponse(request, "home.j2", context)


@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, user: dict = Depends(require_current_user)) -> HTMLResponse:
    """Show the signed-in user's identity."""
    return templates.TemplateResponse(request, "profile.j2", {"user": user})


def sign_in_error_message(exc: OAuthError) -> str:
    """Return the home-page banner text for a failed Entra callback."""
    if description := (exc.description or "").strip():
        return description
    if exc.error:
        return exc.error.replace("_", " ")
    return "Sign-in failed."


@app.get("/login")
async def login(request: Request) -> RedirectResponse:
    """Redirect the browser to Entra to start the authorization code flow."""
    return await oauth.entra.authorize_redirect(request, REDIRECT_URI)


@app.get("/auth/callback")
async def auth_callback(request: Request) -> RedirectResponse:
    """Store the Entra identity, set the session cookie, and redirect home."""
    try:
        token = await oauth.entra.authorize_access_token(request)
    except OAuthError as exc:
        request.session["err_msg"] = sign_in_error_message(exc)
        return RedirectResponse("/", status_code=302)

    # Authlib validates the OIDC ID token and provides userinfo.
    if not (userinfo := token.get("userinfo")):
        raise HTTPException(
            status_code=401, detail="Unable to retrieve authenticated user information"
        )

    # Store only the identity claims we need.
    user = {
        "name": userinfo.get("name"),
        "username": (userinfo.get("preferred_username") or userinfo.get("email")),
        "oid": userinfo.get("oid"),
        "tid": userinfo.get("tid"),
        "roles": userinfo.get("roles"),
        "login_hint": userinfo.get("login_hint"),
    }

    # Start a fresh application session after successful authentication.
    request.session.clear()
    request.session["csrf_token"] = secrets.token_urlsafe(32)

    session_id = create_session(user)

    response = RedirectResponse("/", status_code=302)
    touch_session_cookie(session_id, response)

    return response


def clear_local_session(request: Request, response: RedirectResponse) -> RedirectResponse:
    """Delete the SQLite session and the session_id cookie, then return response."""
    # wipe refresh in case get_current_user has marked this request for a cookie slide.
    request.state.refresh_session_id = None
    if session_id := request.cookies.get("session_id"):
        delete_session(session_id)

    response.delete_cookie(
        key="session_id",
        path="/",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="lax",
    )

    return response


@app.post("/logout", dependencies=[Depends(require_csrf)])
async def logout(request: Request) -> RedirectResponse:
    """End the local session and redirect home with a logout banner."""
    request.session.clear()
    request.session["info_msg"] = "You have been logged out"
    return clear_local_session(request, RedirectResponse("/", status_code=303))


@app.post("/logout/entra", dependencies=[Depends(require_csrf)])
async def logout_entra(request: Request) -> RedirectResponse:
    """Clear the local session and sign out through Entra."""
    request.session.clear()

    params = {"post_logout_redirect_uri": POST_LOGOUT_URI}
    if (
        (user := get_session(request.cookies.get("session_id")))
        and isinstance(login_hint := user.get("login_hint"), str)
        and login_hint
    ):
        params["logout_hint"] = login_hint

    logout_url = f"{ENTRA_LOGOUT_ENDPOINT}?{urlencode(params)}"

    return clear_local_session(request, RedirectResponse(logout_url, status_code=303))


@app.get("/logged-out")
async def logged_out(request: Request) -> RedirectResponse:
    """Record the Entra logout banner and redirect home."""
    request.session["info_msg"] = "You have been logged out"
    return RedirectResponse("/")


@app.get(
    "/admin/sessions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_role(App.Admin))],
)
async def admin_sessions(request: Request) -> HTMLResponse:
    """List active sessions for users with App.Admin."""

    context = {
        "sessions": list_sessions(request.cookies.get("session_id")),
        "csrf_token": get_csrf_token(request),
    }
    return templates.TemplateResponse(request, "sessions.j2", context)


@app.post(
    "/admin/sessions/delete",
    dependencies=[Depends(require_role(App.Admin)), Depends(require_csrf)],
)
async def admin_delete_session(
    request: Request,
    session_row_id: int = Form(...),
) -> RedirectResponse:
    """Delete one session by SQLite row id and redirect back."""

    session_id = request.cookies.get("session_id")
    removed = delete_session_row(session_row_id)
    if session_id and removed == hash_session_id(session_id):
        return clear_local_session(request, RedirectResponse("/", status_code=303))

    return RedirectResponse("/admin/sessions", status_code=303)


@app.get("/health")
async def health() -> dict:
    """Report that the process is up and how many seconds it has been running."""
    uptime_seconds = int(time.monotonic() - STARTED_AT)
    return {"status": "healthy", "uptime_seconds": uptime_seconds}

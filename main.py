import os
from pathlib import Path
from urllib.parse import urlencode

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader, select_autoescape
from starlette.middleware.sessions import SessionMiddleware
from session_store import (
    create_session,
    list_sessions,
    get_session,
    delete_session,
    delete_session_row,
)

load_dotenv()

TENANT_ID = os.environ["ENTRA_TENANT_ID"]
CLIENT_ID = os.environ["ENTRA_CLIENT_ID"]
CLIENT_SECRET = os.environ["ENTRA_CLIENT_SECRET"]
SESSION_SECRET = os.environ["SESSION_SECRET"]

REDIRECT_URI = "https://app.alexglass.com/auth/callback"
POST_LOGOUT_URI = "https://app.alexglass.com/logged-out"

ENTRA_LOGOUT_ENDPOINT = (
    f"https://login.microsoftonline.com/{TENANT_ID}" "/oauth2/v2.0/logout"
)

app = FastAPI(title="FastAPI SSO Lab")
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).resolve().parent / "static"),
    name="static",
)
templates = Jinja2Templates(
    env=Environment(
        loader=FileSystemLoader(Path(__file__).resolve().parent / "templates"),
        # .j2 is outside Jinja's default HTML autoescape suffixes.
        autoescape=select_autoescape(enabled_extensions=("html", "htm", "xml", "j2")),
    )
)

# Signed session cookie
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="fastapi_sso_session",
    max_age=3600,
    same_site="lax",
    https_only=True,
)

# OIDC provider configuration
oauth = OAuth()

oauth.register(
    name="entra",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=(
        f"https://login.microsoftonline.com/{TENANT_ID}"
        "/v2.0/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid profile email",
    },
)


def sign_in_error_message(exc: OAuthError) -> str:
    description = (exc.description or "").strip()
    if description:
        return description
    if exc.error:
        return exc.error.replace("_", " ")
    return "Sign-in failed."


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session_id = request.cookies.get("session_id")
    user = get_session(session_id)
    if err_msg := request.session.pop("err_msg", None):
        banner = err_msg
        banner_role = "alert"
    else:
        if info_msg := request.session.pop("info_msg", None):
            banner = info_msg
            banner_role = "info"
        else:
            banner = None
            banner_role = None

    return templates.TemplateResponse(
        request, "home.j2", {"user": user, "banner": banner, "banner_role": banner_role}
    )


@app.get("/login")
async def login(request: Request):
    return await oauth.entra.authorize_redirect(
        request,
        REDIRECT_URI,
    )


async def get_current_user(request: Request):
    session_id = request.cookies.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
        )

    user = get_session(session_id)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Session expired or invalid",
        )

    return user


@app.get("/profile")
async def profile(user: dict = Depends(get_current_user)):
    return {
        "message": "You are authenticated",
        "user": user,
    }


@app.get("/auth/callback")
async def auth_callback(request: Request):
    try:
        token = await oauth.entra.authorize_access_token(request)
    except OAuthError as exc:
        request.session["err_msg"] = sign_in_error_message(exc)
        return RedirectResponse("/", status_code=302)

    # Authlib validates the OIDC ID token and provides userinfo.
    userinfo = token.get("userinfo")

    if not userinfo:
        raise HTTPException(
            status_code=401,
            detail="Unable to retrieve authenticated user information",
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

    session_id = create_session(user)

    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=3600,
    )

    return response


def require_role(required_role: str):
    async def role_checker(
        user: dict = Depends(get_current_user),
    ):
        if required_role not in user["roles"]:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )

        return user

    return role_checker


def clear_local_session(
    request: Request, response: RedirectResponse
) -> RedirectResponse:
    session_id = request.cookies.get("session_id")
    if session_id:
        delete_session(session_id)
    response.delete_cookie(
        key="session_id",
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )
    return response


@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    request.session["info_msg"] = "You have been logged out"
    return clear_local_session(request, RedirectResponse("/", status_code=302))


@app.get("/logout/entra")
async def logout_entra(request: Request):
    """Clear the local session and sign out through Entra."""
    request.session.clear()

    user = get_session(request.cookies.get("session_id"))
    login_hint = user.get("login_hint") if user else None
    params = {"post_logout_redirect_uri": POST_LOGOUT_URI}
    if isinstance(login_hint, str) and login_hint:
        params["logout_hint"] = login_hint

    logout_url = f"{ENTRA_LOGOUT_ENDPOINT}?{urlencode(params)}"

    return clear_local_session(request, RedirectResponse(logout_url, status_code=302))


@app.get("/logged-out")
async def logged_out(request: Request):
    request.session["info_msg"] = "You have been logged out"
    return RedirectResponse("/")


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/reports")
async def reports(
    user: dict = Depends(require_role("App.Reader")),
):
    return {
        "message": "Report 0123",
    }


@app.get("/admin/sessions", response_class=HTMLResponse)
async def admin_sessions(
    request: Request,
    user: dict = Depends(require_role("App.Admin")),
):
    return templates.TemplateResponse(
        request,
        "sessions.j2",
        {"sessions": list_sessions(request.cookies.get("session_id"))},
    )


@app.post("/admin/sessions/delete")
async def admin_delete_session(
    request: Request,
    session_row_id: int = Form(...),
    user: dict = Depends(require_role("App.Admin")),
):
    deleted_session_id = delete_session_row(session_row_id)
    deleting_current = deleted_session_id == request.cookies.get("session_id")

    if deleting_current:
        return clear_local_session(request, RedirectResponse("/", status_code=303))

    return RedirectResponse(
        "/admin/sessions",
        status_code=303,
    )

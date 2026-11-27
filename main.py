import os
from html import escape

from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import urlencode
from session_store import create_session, list_sessions, get_session, delete_session

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


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session_id = request.cookies.get("session_id")
    user = get_session(session_id)

    if not user:
        return """
        <html>
            <head><title>FastAPI SSO Lab</title></head>
            <body>
                <h1>FastAPI SSO Lab</h1>
                <p>You are not signed in.</p>
                <a href="/login">
                    <button>Sign in with Microsoft</button>
                </a>
            </body>
        </html>
        """

    return f"""
    <html>
        <head><title>FastAPI SSO Lab</title></head>
        <body>
            <h1>Welcome, {escape(str(user.get('name') or 'User'))}</h1>
            <p>Username: {escape(str(user.get('username') or ''))}</p>
            <p>Object ID: {escape(str(user.get('oid') or ''))}</p>
            <p>Tenant ID: {escape(str(user.get('tid') or ''))}</p>
            <p>Roles: {escape(str(user.get('roles') or []))}</p>

            <hr>

            <h3>Sign out</h3>
            <a href="/logout">
                <button>Local logout</button>
            </a>

            <a href="/logout/entra">
                <button>Sign out of Microsoft too</button>
            </a>

            <a href="/admin/sessions">
                <button>Session Admin</button>
            </a>            
        </body>
    </html>
    """


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
    token = await oauth.entra.authorize_access_token(request)

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
    return clear_local_session(request, RedirectResponse("/", status_code=302))


@app.get("/logout/entra")
async def logout_entra(request: Request):
    """Clear the local session and sign out through Entra."""
    request.session.clear()

    params = urlencode({"post_logout_redirect_uri": POST_LOGOUT_URI})
    logout_url = f"{ENTRA_LOGOUT_ENDPOINT}?{params}"

    return clear_local_session(request, RedirectResponse(logout_url, status_code=302))


@app.get("/logged-out")
async def logged_out():
    return {
        "message": "You have been logged out",
        "authenticated": False,
    }


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
    user: dict = Depends(require_role("App.Admin")),
):
    sessions = list_sessions()

    items = "\n".join(
        f"""
        <li>
            {escape(str(session['user'].get('username', '')))}
            — {escape(session['expires_at'].isoformat())}

            <form method="post" action="/admin/sessions/delete"
                  style="display:inline">
                <input type="hidden" name="session_id"
                       value="{escape(session['session_id'])}">
                <button type="submit">Delete</button>
            </form>
        </li>
        """
        for session in sessions
    )

    return f"""
    <html>
        <head><title>FastAPI SSO Lab - Sessions Admin</title></head>
        <body>
            <h1>Sessions Admin</h1>
            <ul>
                {items or "<li>No active sessions</li>"}
            </ul>
        </body>
    </html>
    """


@app.post("/admin/sessions/delete")
async def admin_delete_session(
    session_id: str = Form(...),
    user: dict = Depends(require_role("App.Admin")),
):
    delete_session(session_id)

    return RedirectResponse(
        "/admin/sessions",
        status_code=303,
    )

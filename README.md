# FastAPI SSO with Microsoft Entra

A small demo of signing into a FastAPI app with Microsoft Entra ID using OpenID Connect.

The app uses the authorization code flow through [Authlib](https://docs.authlib.org/). After Entra authenticates the user, FastAPI stores the identity in SQLite and sets an `HttpOnly` `session_id` cookie. That cookie is an opaque lookup key, not a signed document. A separate signed cookie holds only the OAuth `state` and one-time page messages.

A session lasts one hour. A request that finds a live session extends the SQLite row by another hour. Middleware then sets `session_id` again on the response the route returned, with a new one-hour `Max-Age`. The cookie has to be set there because pages such as home return their own `HTMLResponse`, and a cookie written earlier in the request is dropped. Sign-out clears that refresh so the cookie is not sent again on the way out.

## What the demo includes

- Sign in with Microsoft and sign out locally, or through Entra as well.
- A home page that shows the signed-in user and their app roles.
- An admin page at `/admin/sessions` for users with `App.Admin`. It lists active sessions and can delete them. The session cookie value stays in the database. The page uses the SQLite row id.

Sign-out sends the ID token `login_hint` claim as `logout_hint` so Entra can end the right session without an account picker.

## Setup

Install [uv](https://docs.astral.sh/uv/), then from the project root:

```bash
uv sync --group dev
cp .env.example .env   # if present; otherwise create .env with required variables
uv run pre-commit install
```

Required environment variables: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `SESSION_SECRET`, and `APP_BASE_URL`.

`APP_BASE_URL` is the public origin of this app, with no path and no trailing slash, such as `https://login.example.com`. The app builds its Entra redirect URIs from that origin:

- `{APP_BASE_URL}/auth/callback`
- `{APP_BASE_URL}/logged-out`

Register both URIs on the Entra app registration. When `APP_BASE_URL` uses `https`, the session cookies are marked `Secure`. An `http` origin, such as `http://127.0.0.1:8000`, leaves them unset so a local demo can keep the cookies.

### Token configuration

`login_hint` is not in the ID token unless you add it:

1. Open the app in Microsoft Entra admin center.
2. Go to **App registration** → **Token configuration**.
3. Add an optional claim: token type = **ID**, claim = `login_hint`.

The sign-in request already includes the `openid` and `profile` scopes that claim requires. App roles must be emitted in the ID token. `/admin/sessions` allows only `App.Admin`.

## Run

```bash
uv run uvicorn --app-dir lib main:app --reload --host 0.0.0.0 --port 8000
```

## Formatting

Black runs on commit via pre-commit. To format or check manually:

```bash
uv run black .
uv run pre-commit run --all-files
```

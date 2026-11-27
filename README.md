# FastAPI SSO with Microsoft Entra

A small demo of signing into a FastAPI app with Microsoft Entra ID using OpenID Connect.

The app uses the authorization code flow through [Authlib](https://docs.authlib.org/). After Entra authenticates the user, FastAPI stores the identity in SQLite and sets an `HttpOnly` `session_id` cookie. That cookie is an opaque lookup key, not a signed document. A separate signed cookie holds only the OAuth `state` and one-time page messages.

## What the demo includes

- Sign in with Microsoft and sign out locally, or through Entra as well.
- A home page that shows the signed-in user and their app roles.
- Role checks for `App.Reader` (`/reports`) and `App.Admin` (`/admin/sessions`).
- An admin page that lists active sessions and can delete them. The session cookie value stays in the database. The page uses the SQLite row id.

Sign-out sends the ID token `login_hint` claim as `logout_hint` so Entra can end the right session without an account picker.

## Setup

Install [uv](https://docs.astral.sh/uv/), then from the project root:

```bash
uv sync --group dev
cp .env.example .env   # if present; otherwise create .env with required variables
uv run pre-commit install
```

Required environment variables: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `SESSION_SECRET`.

Register these redirect URIs on the Entra app. They are set in `main.py`:

- `https://app.alexglass.com/auth/callback`
- `https://app.alexglass.com/logged-out`

The session cookies are HTTPS-only.

### Token configuration

`login_hint` is not in the ID token unless you add it:

1. Open the app in Microsoft Entra admin center.
2. Go to **App registration** → **Token configuration**.
3. Add an optional claim: token type = **ID**, claim = `login_hint`.

The sign-in request already includes the `openid` and `profile` scopes that claim requires. App roles such as `App.Admin` and `App.Reader` must be emitted in the ID token for the role checks to pass.

## Run

```bash
uv run uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

## Formatting

Black runs on commit via pre-commit. To format or check manually:

```bash
uv run black .
uv run pre-commit run --all-files
```

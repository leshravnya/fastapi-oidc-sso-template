import json

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Depends, HTTPException
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from app.config import settings

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="my-secret1")

config = Config(".env")
oauth = OAuth(config)

CONF_URL = "http://localhost:9090/.well-known/openid-configuration"
oauth.register(
    name="my_oauth",
    server_metadata_url=CONF_URL,
    client_kwargs={"scope": "openid email profile authorization_group"},
    client_id=settings.authentication.client_id,
    client_secret=settings.authentication.client_secret,
)


@app.get("/")
async def homepage(request: Request):
    user = request.session.get("user")
    if user:
        data = json.dumps(user)
        html = f"<pre>{data}</pre>" '<a href="/logout">logout</a>'
        return HTMLResponse(html)
    return HTMLResponse('<a href="/login">login</a>')


@app.get("/login")
async def login(request: Request):
    redirect_uri = request.url_for("auth")
    print(redirect_uri)
    return await oauth.my_oauth.authorize_redirect(request, redirect_uri)


@app.get("/auth")
async def auth(request: Request):
    try:
        token = await oauth.my_oauth.authorize_access_token(request)
    except OAuthError as error:
        return HTMLResponse(f"<h1>{error.error}</h1>")
    user = await oauth.my_oauth.parse_id_token(request, token)
    request.session["user"] = dict(user)
    return RedirectResponse(url="/")


@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    return RedirectResponse(url="/")


async def get_active_user(request: Request):
    user = request.session.get("user")
    if user:
        return user
    else:
        try:
            token = await oauth.my_oauth.authorize_access_token(request)
        except OAuthError as error:
            raise HTTPException(status_code=403, detail=str(error))
        user = await oauth.my_oauth.parse_id_token(request, token)
        request.session["user"] = dict(user)


@app.get("/test-api")
async def test(user=Depends(get_active_user)):
    return HTMLResponse(f"<h1>Hello There {user['sub']}</h1>")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="localhost", port=8000, reload=True)

# main.py

import os
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from requests.auth import HTTPBasicAuth
import requests
import pprint 

from app.auth_provider import AppIDAuthProvider, auth_required
import gradio as gr


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        print("Request URLs:", request.url.path)
        if request.url.path.startswith("/gradio-app"):
            token = request.cookies.get("auth_token")
            print("\n--- Incoming Request ---")
            print("URL Path:", request.url.path)
            print("Method:", request.method)
            print("Headers:")
            pprint.pprint(dict(request.headers))
            print("Cookies:")
            pprint.pprint(request.cookies)
            print("Query Params:")
            pprint.pprint(dict(request.query_params))
            print("------------------------\n")
            # print(request.session["APPID_USER_TOKEN"])
            if token != "valid-token":
                return HTMLResponse(
                    content="""
                        <h3>Unauthorized Access</h3>
                        <a href="/login">Login</a>
                    """,
                    status_code=401
                )
        return await call_next(request)
    
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.environ["SESSION_SECRET_KEY"])
app.add_middleware(AuthMiddleware)


@app.get("/afterauth")
def after_auth(request: Request):
    session = request.session
    code = request.query_params.get("code")
    if not code:
        session[AppIDAuthProvider.AUTH_ERRMSG] = "Missing code from server"
        return RedirectResponse(url="/")

    token_endpoint = f"{AppIDAuthProvider.OAUTH_SERVER_URL}/token"
    resp = requests.post(token_endpoint, data={
        "client_id": AppIDAuthProvider.CLIENT_ID,
        "grant_type": "authorization_code",
        "redirect_uri": AppIDAuthProvider.REDIRECT_URI,
        "code": code
    }, auth=HTTPBasicAuth(AppIDAuthProvider.CLIENT_ID, AppIDAuthProvider.CLIENT_SECRET))

    data = resp.json()
    if "access_token" not in data or "id_token" not in data:
        session[AppIDAuthProvider.AUTH_ERRMSG] = data.get("error_description", "Token exchange failed")
        return RedirectResponse(url="/")

    access_token = data["access_token"]
    email, user_id = AppIDAuthProvider._get_user_info(data["id_token"])
    roles_resp = AppIDAuthProvider._get_user_roles(user_id)
    
    print(user_id)
    print(email)

    if "roles" in roles_resp:
        session[AppIDAuthProvider.APPID_USER_TOKEN] = access_token
        session[AppIDAuthProvider.APPID_USER_ROLES] = roles_resp["roles"]
    else:
        session[AppIDAuthProvider.AUTH_ERRMSG] = roles_resp.get("error_description", "No roles found")

    endpoint = session.pop(AppIDAuthProvider.ENDPOINT_CONTEXT, "/secure-data")
    return RedirectResponse(url=endpoint)

@app.get("/login")
def login(request: Request):
    request.session[AppIDAuthProvider.ENDPOINT_CONTEXT] = "/secure-data"
    url = (
        f"{AppIDAuthProvider.OAUTH_SERVER_URL}/authorization"
        f"?client_id={AppIDAuthProvider.CLIENT_ID}"
        f"&response_type=code"
        f"&redirect_uri={AppIDAuthProvider.REDIRECT_URI}"
        f"&scope=openid"
    )
    return RedirectResponse(url=url)

@app.get("/")
def home():
    return HTMLResponse("<a href='/secure-data'>Login Protected Route</a>")

# Step 4: Define your Gradio interface
def greet(name):
    return f"Hello, {name}!"

demo = gr.Interface(fn=greet, inputs="text", outputs="text")

@app.get("/secure-data")
@auth_required
async def secure_data(request: Request):
    # Step 5: Mount Gradio app using Gradio's official helper
    print(request.session[AppIDAuthProvider.APPID_USER_TOKEN])
    response = RedirectResponse(url="/gradio-app", headers={"Authorization": request.session[AppIDAuthProvider.APPID_USER_TOKEN]})
    response.set_cookie(key="auth_token", value="valid-token")
    return response

gr.mount_gradio_app(app, demo, path="/gradio-app")


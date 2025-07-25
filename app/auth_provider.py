# auth_provider.py

import os
import json
import base64
from functools import wraps

import requests
from requests.auth import HTTPBasicAuth
from fastapi import Request
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv

load_dotenv()

class AppIDAuthProvider:
    APPID_MGMT_TOKEN = ""
    CLIENT_ID = os.environ["APPID_CLIENT_ID"]
    CLIENT_SECRET = os.environ["APPID_CLIENT_SECRET"]
    REDIRECT_URI = os.environ["APPID_REDIRECT_URI"]
    OAUTH_SERVER_URL = os.environ["APPID_OAUTH_SERVER_URL"]
    MANAGEMENT_URL = OAUTH_SERVER_URL.replace("oauth", "management")
    IAM_TOKEN_ENDPOINT = "https://iam.cloud.ibm.com/identity/token"

    APPID_USER_TOKEN = "APPID_USER_TOKEN"
    APPID_USER_ROLES = "APPID_USER_ROLES"
    AUTH_ERRMSG = "AUTH_ERRMSG"
    ENDPOINT_CONTEXT = "ENDPOINT_CONTEXT"

    @staticmethod
    def _base64_decode(data):
        data += '=' * (4 - len(data) % 4)
        return base64.b64decode(data).decode('utf-8')

    @classmethod
    def _get_user_info(cls, id_token):
        decoded = cls._base64_decode(id_token.split('.')[1])
        info = json.loads(decoded)
        return info["email"], info["sub"]

    @classmethod
    def _get_user_roles(cls, user_id):
        resp = cls._exec_user_roles_req(user_id)
        if resp.status_code in [401, 403]:
            err = cls._get_appid_mgmt_access_token()
            if err:
                return {"error_description": err}
            resp = cls._exec_user_roles_req(user_id)
        data = resp.json()
        if "roles" in data:
            return {"roles": [r["name"] for r in data["roles"]]}
        return {"error_description": data.get("Error", {}).get("Status") or data.get("errorCode")}

    @classmethod
    def _exec_user_roles_req(cls, user_id):
        url = f"{cls.MANAGEMENT_URL}/users/{user_id}/roles"
        headers = {"Authorization": f"Bearer {cls.APPID_MGMT_TOKEN}"}
        return requests.get(url, headers=headers)

    @classmethod
    def _get_appid_mgmt_access_token(cls):
        resp = requests.post(cls.IAM_TOKEN_ENDPOINT,
            data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": os.environ["IBM_CLOUD_APIKEY"]})
        data = resp.json()
        if "access_token" in data:
            cls.APPID_MGMT_TOKEN = data["access_token"]
            return ""
        return "could not retrieve App ID management access token" + ", " + data.get("errorCode", "")

    @classmethod
    def _is_auth_active(cls, request: Request):
        session = request.session
        if cls.AUTH_ERRMSG in session:
            return False, session.pop(cls.AUTH_ERRMSG)
        token = session.get(cls.APPID_USER_TOKEN)
        if token:
            url = f"{cls.OAUTH_SERVER_URL}/introspect"
            resp = requests.post(url, data={"token": token}, auth=HTTPBasicAuth(cls.CLIENT_ID, cls.CLIENT_SECRET))
            data = resp.json()
            if data.get("active"):
                return True, ""
            session.pop(cls.APPID_USER_TOKEN, None)
            session.pop(cls.APPID_USER_ROLES, None)
            return False, data.get("error_description", "")
        return False, ""

    @classmethod
    def start_auth(cls, request: Request):
        request.session[cls.ENDPOINT_CONTEXT] = str(request.url)
        url = f"{cls.OAUTH_SERVER_URL}/authorization?client_id={cls.CLIENT_ID}&response_type=code&redirect_uri={cls.REDIRECT_URI}&scope=openid"
        return RedirectResponse(url=url)

    @classmethod
    def _user_has_a_role(cls, request: Request):
        return bool(request.session.get(cls.APPID_USER_ROLES))


def auth_required(endpoint_func):
    @wraps(endpoint_func)
    async def wrapper(request: Request, *args, **kwargs):
        auth_active, err_msg = AppIDAuthProvider._is_auth_active(request)
        if not auth_active:
            if err_msg:
                return {"error": f"Internal error: {err_msg}"}
            else:
                # Redirect to login page
                return RedirectResponse(url="/login")
        else:
            if not AppIDAuthProvider._user_has_a_role(request):
                return {"error": "Unauthorized!"}
            else:
                return await endpoint_func(request, *args, **kwargs)
    return wrapper

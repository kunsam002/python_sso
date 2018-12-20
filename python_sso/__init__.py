import os
import base64
from datetime import datetime, timedelta

import requests
import g


class VGGSSO:
    """the custom SSO (Single Sign On) object to be used by all apps for authentication and authorization
    within the VGG eco-system"""

    def __init__(self, app, client_id=None, client_secret=None, client_username=None, client_password=None):
        self.app = app
        self.client_id = client_id if client_id else self.app.config.get("VGG_SSO_CLIENT_ID", None)
        self.client_secret = client_secret if client_secret else self.app.config.get("VGG_SSO_CLIENT_SECRET", None)
        self.client_username = client_username if client_username else self.app.config.get("VGG_SSO_CLIENT_USERNAME",
                                                                                           None)
        self.client_password = client_password if client_password else self.app.config.get("VGG_SSO_CLIENT_PASSWORD",
                                                                                           None)

        self.token_url = app.config.get("VGG_SSO_TOKEN_URL", "http://sso.test.vggdev.com/identity/connect/token")
        self.api_base_url = app.config.get("VGG_SSO_API_BASE_URL", "https://ssoapi.test.vggdev.com")

    def get_access_token(self):
        """ logic for the get access token function """
        auth_key = base64.b64encode(bytes('%s:%s' % (self.client_id, self.client_secret), "utf-8"))
        headers = {"Authorization": "Basic %s" % auth_key, "Content-Type": "application/json"}
        data = {
            "grant_type": "password",
            "username": self.client_username,
            "password": self.client_password,
            "scope": "openid profile identity-server-api"
        }
        resp = requests.post(self.token_url, headers=headers, data=data)

        token_type, access_token, expires_in = None, None, None

        # On success response
        if resp.status_code in [200, 201]:
            token_type, access_token, expires_in = resp.content.get("token_type"), resp.content.get(
                "access_token"), resp.content.get("expires_in")

        # Calculating the access_token expiration and saving to session for subsequent requests
        if expires_in:
            expires_in_hr = expires_in / 60
            token_expiration = datetime.now() + timedelta(minutes=expires_in_hr)
            self.token_expiration = token_expiration
            g.token_expiration = token_expiration

        return token_type, access_token

    @staticmethod
    def check_required_fields(fields, data):
        """ method to check all required fields are passed to the post action """

        if not all(key in data for key in fields):
            return False

        return True

    def post(self, suffix, data):
        """
        handles every post request by the class object as well as process post response

        params:
            suffix - url resource name extension
            data - payload to be posted
        """
        url = self.api_base_url + suffix
        token_type, access_token = self.get_access_token()

        headers = headers = {"Authorization": "%s %s" % (token_type, access_token), "Content-Type": "application/json",
                             "client-id": self.client_id}

        resp = requests.post(url, headers=headers, data=data)

        return resp.status_code, resp.content

    def account_register(self, data):
        """
        account registration on the SSO Identity server

        params:
            data - payload to be posted
        """

        required_fields = ["FirstName", "LastName", "UserName", "Email", "Password", "PhoneNumber", "ConfirmEmail",
                           "Claims"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/register"

        return self.post(suffix, data)

    def account_generate_confirm_token(self, data):
        """
        method to re-generate an account confirmation token

        params:
            data - payload to be posted
        """

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/generateconfirmtoken"

        return self.post(suffix, data)

    def account_confirm(self, data):
        """
        method to confirm an account with provided token

        params:
            data - payload to be posted
        """

        required_fields = ["UserId", "Token"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/confirm"

        return self.post(suffix, data)

    def account_update(self, data):
        """
        method to update account details

        params:
            data - payload to be posted
        """

        required_fields = ["FirstName", "LastName", "UserName", "Email", "PhoneNumber"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/update"

        return self.post(suffix, data)

    def account_add_claims(self, data):
        """
        method to associate account claims to clients and applications profiled on the Identity Server SSO

        params:
            data - payload to be posted
        """

        required_fields = ["UserId", "Claims"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/addclaims"

        return self.post(suffix, data)

    def account_remove_claims(self, data):
        """
        method to revoke account claims to clients and applications profiled on the Identity Server SSO

        params:
            data - payload to be posted
        """

        required_fields = ["UserId", "Claims"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/removeclaims"

        return self.post(suffix, data)

    def account_reset_password(self, data):
        """
        method to reset account password

        params:
            data - payload to be posted
        """

        required_fields = ["UserId", "Token", "NewPassword"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/resetpassword"

        return self.post(suffix, data)

    def account_change_password(self, data):
        """
        method to change account password

        params:
            data - payload to be posted
        """

        required_fields = ["UserId", "CurrentPassword", "NewPassword"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/changepassword"

        return self.post(suffix, data)

    def account_users_by_claim(self, data):
        """
        method to fetch and query all accounts with respect to claims

        params:
            data - payload to be posted
        """

        required_fields = ["Type", "Value"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(message="Missing required key value"))

        suffix = "/account/usersbyclaim"

        return self.post(suffix, data)

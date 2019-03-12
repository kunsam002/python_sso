"""
__init__.py

@Author: Olukunle Ogunmokun
@Date: 19th Dec, 2018
Last Modified: 18th Feb, 2019

SSO Identity Server Integration Library
"""

import os
import base64
from datetime import datetime, timedelta
import requests
import json
import urllib


class SSOAccess:
    """
    The custom object to handle access calls and requests to the SSO Identity Server
    """

    def __init__(self, debug=True, config_data={}):
        self.client_id = config_data.get("VGG_SSO_CLIENT_ID",
                                         None)  # Fetch the Client ID with Client Credentials Access point
        self.client_secret = config_data.get("VGG_SSO_CLIENT_SECRET",
                                             None)  # Fetch the Client Secret with Client Credentials Access Point
        self.client_ro_id = config_data.get("VGG_SSO_CLIENT_RO_ID",
                                            None)  # Fetch the Client ID with Resource Owner Access Point
        self.client_ro_secret = config_data.get("VGG_SSO_CLIENT_RO_SECRET",
                                                None)  # Fetch the Client Secret with Resource Owner Access Point

        custom_token_base_url = config_data.get("TOKEN_BASE_URL", None)  # Fetch the Token Base URL as a custom url
        custom_api_base_url = config_data.get("API_BASE_URL", None)  # Fetch the API Base URL as a custom url

        self.debug = debug
        self.actor = "cc"

        # Check to validate the a value was provided for VGG_SSO_CLIENT_ID
        if not self.client_id:
            raise Exception("Invalid VGG_SSO_CLIENT_ID provided")

        # Check to validate the a value was provided for VGG_SSO_CLIENT_SECRET
        if not self.client_secret:
            raise Exception("Invalid VGG_SSO_CLIENT_SECRET provided")

        """
        Checks to validate if library is being used on staging or production environment. Default set as True
        debug = True representing staging environment
        debug = False representing production environment
        """
        if self.debug:
            self.token_base_url = "http://sso.test.vggdev.com"
            self.api_base_url = "https://ssoapi.test.vggdev.com"
        else:
            self.token_base_url = "https://sso.venturegardengroup.com"
            self.api_base_url = "https://ssoapi.venturegardengroup.com"

        if custom_token_base_url:
            self.token_url = custom_token_base_url + "/identity/connect/token"
        else:
            self.token_url = self.token_base_url + "/identity/connect/token"

        if custom_api_base_url:
            self.api_base_url = custom_api_base_url

        self.client_token_type = None
        self.client_access_token = None
        self.client_token_expiration = None

        self.token_type = None
        self.access_token = None
        self.token_expiration = None

        self.username = None

    @staticmethod
    def binary_to_dict(the_binary):
        """
        Attempts to convert a given byte string to a json object
        :param the_binary:
        :return:
        """

        jsn = ''.join(chr(int(x, 2)) for x in the_binary.split())
        d = json.loads(jsn)

        return d

    def process_response_content(self, resp_cont):
        # Attempts to clean the response and unify the response structure gotten from the SSO Identity Server
        if type(resp_cont) == str:
            try:
                resp_cont = json.loads(resp_cont)
            except:
                pass
        elif type(resp_cont) == bytes:
            try:
                resp_cont = self.binary_to_dict(resp_cont)
            except:
                pass

        elif type(resp_cont) in [str, bytes]:
            try:
                resp_cont = json.loads(resp_cont.decode())
            except:
                pass
        else:
            pass

        try:
            resp_cont = json.loads(resp_cont)
        except:
            pass

        return resp_cont

    def get_access_token(self, obj_client_username=None, obj_client_password=None):
        """ logic for the get access token function """

        time_now = datetime.now()

        # Checks for previously generated access token and the validity of the access token
        if self.actor == "ro" and self.token_expiration and self.token_type and self.access_token and self.token_expiration > time_now:
            return dict(token_type=self.token_type, access_token=self.access_token)

        # Checks for previously generated access token and the validity of the access token
        if self.actor == "cc" and self.client_token_expiration and self.client_token_type and self.client_access_token and self.client_token_expiration > time_now:
            return dict(token_type=self.client_token_type, access_token=self.client_access_token)

        key = ""

        if self.actor == "ro":
            key = '%s:%s' % (self.client_ro_id, self.client_ro_secret)
        if self.actor == "cc":
            key = '%s:%s' % (self.client_id, self.client_secret)

        auth_key = base64.b64encode(bytes(key.encode()))

        headers = {"Authorization": "Basic %s" % str(auth_key.decode("utf-8")),
                   "Content-Type": "application/x-www-form-urlencoded"}

        data = {
            "grant_type": "password" if self.actor == "ro" else "client_credentials",
            "username": obj_client_username if obj_client_username else "",
            "password": obj_client_password if obj_client_password else "",
            "scope": "openid profile identity-server-api" if self.actor == "ro" else "identity-server-api"
        }

        if self.actor == "cc":
            data.pop("username")
            data.pop("password")

        resp = requests.post(self.token_url, headers=headers, data=data)

        token_type, access_token, expires_in, token_expiration, error = None, None, None, None, None

        resp_content = resp.content

        # Cleanup response content
        resp_content = self.process_response_content(resp_content)

        # On success response
        if resp.status_code in [200, 201]:
            token_type, access_token, expires_in = resp_content.get("token_type", None), resp_content.get(
                "access_token", None), resp_content.get("expires_in", None)
        else:
            error = resp_content.get("error", None)

        # Calculating the access_token expiration and saving to session for subsequent requests
        if expires_in:
            expires_in_min = expires_in / 60
            token_expiration = time_now + timedelta(minutes=expires_in_min - 1)

        """
         Checks the access point with ro representing Resource Owner and cc representing Client Credentials
        """

        # Attempts to save the token_type, token_expiration and access_token associated with the Resource Owner Access Point
        if self.actor == "ro":
            self.token_expiration = token_expiration
            self.token_type = token_type
            self.access_token = access_token

        # Attempts to save the token_type, token_expiration and access_token associated with the Client Credential Access Point
        if self.actor == "cc":
            self.client_token_expiration = token_expiration
            self.client_token_type = token_type
            self.client_access_token = access_token

        return dict(code=resp.status_code, content=resp_content, token_type=token_type,
                    token_expiration=token_expiration, access_token=access_token, error=error)


class VGGSSO(SSOAccess):
    """
    The custom SSO (Single Sign On) object to be used by all apps for authentication and authorization
    within the VGG eco-system
    """

    @staticmethod
    def check_required_fields(fields, data):
        """
        method to check all required fields are passed to the post action

        params:
            data - payload to be validated as having all required fields before posting
        """

        if not all(key in data for key in fields):
            return False

        return True

    def login(self, username=None, password=None, authorization=None):
        """
        logic to process user login as a resource owner

        params:
            username - username associated with an existing user
            password - password associated with an existing user
        """

        self.actor = "ro"

        time_now = datetime.now()

        error = None
        token_resp = {"error": error, "token_expiration": self.token_expiration, "token_type": self.token_type,
                      "access_token": self.access_token}

        # Checks if there is an already existing token and if the token is still valid and yet to expire
        if self.token_expiration and self.token_type and self.access_token and self.token_expiration > time_now and self.username == username:
            if authorization and authorization != "%s %s" % (self.token_type, self.access_token):
                raise Exception("Invalid Authorization provided")
            pass
        else:
            """
            Attempts to generate a fresh access token to the user
            """
            if None in [username, password]:
                self.token_type = None
                self.token_expiration = None
                self.access_token = None
                self.username = None
                raise Exception("Kindly provide valid login credentials")

            # Calls get access token to re-generate an access token to the particular user via the resource owner
            token_resp = self.get_access_token(obj_client_username=username, obj_client_password=password)

            token_type, token_expiration, access_token, error = token_resp.get("token_type", None), token_resp.get(
                "token_expiration", None), token_resp.get("access_token", None), token_resp.get("error", None)

            self.token_type = token_type
            self.token_expiration = token_expiration
            self.access_token = access_token
            self.username = username

            if not access_token:
                self.token_type = None
                self.token_expiration = None
                self.access_token = None
                self.username = None

        return token_resp

    def post(self, suffix, payload, authorization=None):
        """
        handles every post request by the class object as well as process post response

        params:
            suffix - url resource name extension
            payload - payload to be posted
        """

        url = self.api_base_url + suffix

        # Checks access point actors to better determine how to get access token
        if authorization == None and self.actor == "ro":
            token_resp = self.login()
            token_type, token_expiration, access_token, error = token_resp.get("token_type", None), token_resp.get(
                "token_expiration", None), token_resp.get("access_token", None), token_resp.get("error", None)
        elif self.actor == "cc":
            token_resp = self.get_access_token()
            token_type, token_expiration, access_token = token_resp.get("token_type", None), token_resp.get(
                "token_expiration", None), token_resp.get("access_token", None)

        else:
            token_type, access_token = None, None

        if not authorization:
            authorization = "%s %s" % (token_type, access_token)

        headers = {"Authorization": authorization, "Content-Type": "application/json",
                   "client-id": self.client_ro_id}

        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload))
        except Exception as e:
            return 403, {"error": "%s" % e}

        resp_cont = resp.content

        # Cleanup response content
        resp_cont = self.process_response_content(resp_cont)

        return resp.status_code, resp_cont

    def get(self, suffix, data, authorization=None):
        """
        handles every post request by the class object as well as process post response

        params:
            suffix - url resource name extension
            data - params to be built on url
        """

        url = "%s%s?%s" % (self.api_base_url, suffix, urllib.parse.urlencode(data))

        # Checks access point actors to better determine how to get access token
        if authorization:
            pass
        else:
            if self.actor == "ro":
                token_resp = self.login()
                token_type, token_expiration, access_token, error = token_resp.get("token_type", None), token_resp.get(
                    "token_expiration", None), token_resp.get("access_token", None), token_resp.get("error", None)
            elif self.actor == "cc":
                token_resp = self.get_access_token()
                token_type, token_expiration, access_token = token_resp.get("token_type", None), token_resp.get(
                    "token_expiration", None), token_resp.get("access_token", None)

            else:
                token_type, access_token = None, None

            authorization = "%s %s" % (token_type, access_token)

        headers = {"Authorization": authorization, "Content-Type": "application/json",
                   "client-id": self.client_ro_id}

        try:
            resp = requests.get(url, headers=headers)
        except Exception as e:
            return 403, {"error": "%s" % e}

        resp_cont = resp.content

        # Cleanup response content
        resp_cont = self.process_response_content(resp_cont)

        return resp.status_code, resp_cont

    def account_register(self, data, authorization=None):
        """
        account registration on the SSO Identity server

        params:
            data - payload to be posted
        """

        self.actor = "cc"

        required_fields = ["FirstName", "LastName", "UserName", "Email", "Password", "PhoneNumber",
                           "Claims"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        if not data.get("ConfirmEmail", None):
            data["ConfirmEmail"] = True

        suffix = "/account/register"

        status_code, resp_content = self.post(suffix, data)

        try:
            # Situation where user matching email already exist on SSO Identity Server
            if status_code == 302 and type(resp_content) == str and resp_content.count("-") == 4:
                # SSO Identity server returns the matching UserId
                user_id = resp_content

                # Attempt to add new and updated claims to the existing User
                claims = data.get("Claims")
                resp_content = dict(UserId=resp_content)

                addclaims_data = {"UserId": user_id, "Claims": claims}

                _code, _resp = self.account_add_claims(addclaims_data, authorization=authorization)
                print("-------code from add claims----------", _code)
                print("-------resp from add claims-----------", _resp)

                return status_code, resp_content

            return status_code, resp_content

        except:
            pass

        return status_code, resp_content

    def account_forgot_password(self, raw_data):
        """
        method to request a forgot password

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "cc"

        required_fields = ["email"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/forgotpassword"

        data = {"email": raw_data.get("email", "")}

        return self.get(suffix, data)

    def account_reset_password(self, data):
        """
        method to reset account password

        params:
            data - payload to be posted
        """

        self.actor = "cc"

        required_fields = ["UserId", "Token", "NewPassword"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/resetpassword"

        return self.post(suffix, data)

    def account_generate_confirm_token(self, data, authorization=None):
        """
        method to re-generate an account confirmation token

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/generateconfirmtoken"

        url = self.api_base_url + suffix + "?userId=%s" % data.get("userId")

        if not authorization:
            token_resp = self.get_access_token()
            token_type, token_expiration, access_token = token_resp.get("token_type", None), token_resp.get(
                "token_expiration", None), token_resp.get("access_token", None)
            authorization = "%s %s" % (token_type, access_token)

        headers = {"Authorization": authorization, "Content-Type": "application/json",
                   "client-id": self.client_id}

        try:
            resp = requests.post(url, headers=headers, data={})
        except Exception as e:
            return 403, {"error": "%s" % e}

        resp_cont = resp.content

        # Cleanup response content
        resp_cont = self.process_response_content(resp_cont)

        return resp.status_code, resp_cont

    def account_confirm(self, data, authorization=None):
        """
        method to confirm an account with provided token

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["UserId", "Token"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/confirm"

        return self.post(suffix, data, authorization=authorization)

    def account_update(self, data, authorization=None):
        """
        method to update account details

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["FirstName", "LastName", "UserName", "Email", "PhoneNumber"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/update"

        return self.post(suffix, data, authorization=authorization)

    def account_add_claims(self, data, authorization=None):
        """
        method to associate account claims to clients and applications profiled on the Identity Server SSO

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["UserId", "Claims"]

        if self.access_token:
            authorization = "%s %s" % (self.token_type, self.access_token)
        elif self.client_access_token:
            authorization = "%s %s" % (self.client_token_type, self.client_access_token)
        else:
            authorization = None

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/addclaims"

        # return self.post(suffix, data, authorization=authorization)

        url = self.api_base_url + suffix

        headers = {"Authorization": authorization, "Content-Type": "application/json",
                   "client-id": self.client_ro_id}

        try:
            resp = requests.post(url, headers=headers, data=json.dumps(data))
        except Exception as e:
            return 403, {"error": "%s" % e}

        resp_cont = resp.content

        # Cleanup response content
        resp_cont = self.process_response_content(resp_cont)

        return resp.status_code, resp_cont

    def account_remove_claims(self, data, authorization=None):
        """
        method to revoke account claims to clients and applications profiled on the Identity Server SSO

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["UserId", "Claims"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/removeclaims"

        return self.post(suffix, data, authorization=authorization)

    def account_change_password(self, data, authorization=None):
        """
        method to change account password

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["UserId", "CurrentPassword", "NewPassword"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/changepassword"

        return self.post(suffix, data, authorization=authorization)

    def account_users_by_claim(self, data, authorization=None):
        """
        method to fetch and query all accounts with respect to claims

        params:
            data - payload to be posted
        """

        self.actor = "ro"

        required_fields = ["Type", "Value"]

        if not self.check_required_fields(required_fields, data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/usersbyclaim"

        return self.post(suffix, data, authorization=authorization)

    def account_get_user(self, raw_data, authorization=None):
        """
        method to get an individual user record by userId

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/getuser"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_get_user_by_mail(self, raw_data, authorization=None):
        """
        method to get an individual user record by account email

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["email"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/getuserbyemail"

        data = {"email": raw_data.get("email", ""), "pageNo": raw_data.get("pageNo", 1),
                "pageSize": raw_data.get("pageSize", 100)}

        return self.get(suffix, data, authorization=authorization)

    def account_get_user_by_username(self, raw_data, authorization=None):
        """
        method to get an individual user record by account username

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "cc"

        required_fields = ["username"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/getuserbyusername"

        data = {"username": raw_data.get("username", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_get_users(self, raw_data, authorization=None):
        """
        method to query all user records

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        suffix = "/account/getusers"

        data = {"pageNo": raw_data.get("pageNo", 1),
                "pageSize": raw_data.get("pageSize", 50)}

        # Handle blank value for key letter on url, because it breaks the flow
        if raw_data.get("letter", None):
            data["letter"] = raw_data.get("letter", "")

        return self.get(suffix, data, authorization=authorization)

    def account_user_claims(self, raw_data, authorization=None):
        """
        method to query user accounts by claims

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/userclaims"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_lock(self, raw_data, authorization=None):
        """
        method to lock a user account

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/lock"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_unlock(self, raw_data, authorization=None):
        """
        method to unlock a user account

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/unlock"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_enable_two_factor(self, raw_data, authorization=None):
        """
        method to activate a two factor auth on the user account

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/enabletwofactor"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_disable_two_factor(self, raw_data, authorization=None):
        """
        method to deactivate a two factor on the user account

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/disabletwofactor"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_validateuser(self, raw_data, authorization=None):
        """
        method to validate a user account

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/validateuser"

        data = {"userkey": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_anonymous(self, data={}, authorization=None):
        """
        method to return anonymous user

        params:
            data - payload to be processed before building query params
        """

        self.actor = "ro"

        suffix = "/account/anonymous"

        return self.get(suffix, data, authorization=authorization)

    def account_clearance(self, raw_data, authorization=None):
        """
        user account clearance method

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["userId"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/clearance"

        data = {"userId": raw_data.get("userId", "")}

        return self.get(suffix, data, authorization=authorization)

    def account_verifyotp(self, raw_data, authorization=None):
        """
        method to verify otp

        params:
            raw_data - payload to be processed before building query params
        """

        self.actor = "ro"

        required_fields = ["code"]

        if not self.check_required_fields(required_fields, raw_data):
            return dict(status="failed", data=dict(
                message="Check for missing required key from values [%s]" % ", ".join(required_fields)))

        suffix = "/account/verifyotp"

        data = {"code": raw_data.get("code", "")}

        return self.get(suffix, data, authorization=authorization)

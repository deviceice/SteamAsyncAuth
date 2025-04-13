import os
import json
from typing import Dict
from configparser import ConfigParser
import aiofiles
from aiohttp import ClientSession, ClientResponse
from http.cookies import SimpleCookie
from http import HTTPStatus
from base64 import b64encode, b64decode
from rsa import encrypt, PublicKey
import hmac
import struct
from time import time
from hashlib import sha1
from yarl import URL


async def load_steam_guard(steam_guard: str) -> Dict[str, str]:
    if os.path.isfile(steam_guard):
        async with aiofiles.open(steam_guard, 'r') as f:
            content = await f.read()
            return json.loads(content, parse_int=str)
    else:
        return json.loads(steam_guard, parse_int=str)


async def generate_one_time_code(shared_secret: str, timestamp: int = None) -> str:
    if timestamp is None:
        timestamp = int(time())
    time_buffer = struct.pack('>Q', timestamp // 30)  # pack as Big endian, uint64
    time_hmac = hmac.new(b64decode(shared_secret), time_buffer, digestmod=sha1).digest()
    begin = ord(time_hmac[19:20]) & 0xF
    full_code = struct.unpack('>I', time_hmac[begin:begin + 4])[0] & 0x7FFFFFFF  # unpack as Big endian uint32
    chars = '23456789BCDFGHJKMNPQRTVWXY'
    code = ''

    for _ in range(5):
        full_code, i = divmod(full_code, len(chars))
        code += chars[i]

    return code


class SteamUrl:
    API_URL = 'https://api.steampowered.com'
    COMMUNITY_URL = 'https://steamcommunity.com'
    STORE_URL = 'https://store.steampowered.com'
    LOGIN_URL = 'https://login.steampowered.com'


class AuthSteam:

    async def __aenter__(self):
        self.session = ''
        self.session_id = ''
        self.steam_client = ''
        self.steam_id = ''
        self.steam_balance = 0

        self.config = ConfigParser()
        await self._read_config()
        self.session = ClientSession()

        self._API_KEY = self.config['Account']['API_KEY']
        self._username = self.config['Account']['username']
        self._password = self.config['Account']['password']
        self._path_secret_maFile = self.config['Account']['path_secret_maFile']
        self.steam_guard = None
        self.shared_secret = None
        self.refresh_token = None
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def _read_config(self):
        # conf_path = os.path.join(os.path.dirname(__file__), "./account.ini")
        # async with aiofiles.open(conf_path, 'r+') as config_file:
        #     self.config.read_file(config_file)

        conf_path = os.path.join(os.path.dirname(__file__), "./account.ini")
        with open(conf_path, 'r+', encoding='utf-8') as config_file:
            self.config.read_file(config_file)

    async def login(self):
        invalid_client_credentials_is_present = None in (self._username, self._password, self._path_secret_maFile)
        if invalid_client_credentials_is_present:
            raise Exception("Not in log, pass, path in config")
        self.steam_guard = await load_steam_guard(self._path_secret_maFile)
        self.shared_secret = self.steam_guard['shared_secret']
        self.session.cookie_jar.update_cookies({'steamRememberLogin': 'true'})
        login_response = await self._send_login_request()
        login_response = await login_response.json()
        if not login_response['response']:
            raise 'Ошибка авторизациии'
        await self._check_for_captcha(login_response)
        await self._update_steam_guard(login_response)
        finalized_response = await self._finalize_login()
        await self._perform_redirects(finalized_response)
        await self.set_sessionid_cookies()
        return self.session

    async def set_sessionid_cookies(self):
        community_domain = SteamUrl.COMMUNITY_URL[8:]
        store_domain = SteamUrl.STORE_URL[8:]

        community_cookies = self.session.cookie_jar.filter_cookies(SteamUrl.COMMUNITY_URL)
        store_cookies = self.session.cookie_jar.filter_cookies(SteamUrl.STORE_URL)

        for name in ('steamLoginSecure', 'sessionid', 'steamRefresh_steam', 'steamCountry'):
            cookie_value = self.session.cookie_jar.filter_cookies(SteamUrl.COMMUNITY_URL).get(name)
            if cookie_value is None:
                cookie_value = self.session.cookie_jar.filter_cookies(SteamUrl.STORE_URL).get(name)

            if cookie_value:
                if name in ["steamLoginSecure"]:
                    store_cookie = SimpleCookie()
                    store_cookie[name] = store_cookies.get(name, cookie_value.value)
                    store_cookie[name]["domain"] = store_domain
                else:
                    store_cookie = SimpleCookie()
                    store_cookie[name] = cookie_value.value
                    store_cookie[name]["domain"] = store_domain

                if name in ["sessionid", "steamLoginSecure"]:
                    community_cookie = SimpleCookie()
                    community_cookie[name] = community_cookies.get(name, cookie_value.value)
                    community_cookie[name]["domain"] = community_domain
                else:
                    community_cookie = SimpleCookie()
                    community_cookie[name] = cookie_value.value
                    community_cookie[name]["domain"] = community_domain

                # print(store_cookie)
                # print(community_cookie)
                self.session.cookie_jar.update_cookies(store_cookie)
                self.session.cookie_jar.update_cookies(community_cookie)

    async def _api_call(self, method: str, service: str, endpoint: str, version: str = 'v1',
                        params: dict = None) -> ClientResponse:
        url = '/'.join((SteamUrl.API_URL, service, endpoint, version))
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/', 'Origin': SteamUrl.COMMUNITY_URL}
        if method.upper() == 'GET':
            return await self.session.get(url, params=params, headers=headers)
        elif method.upper() == 'POST':
            return await self.session.post(url, data=params, headers=headers)
        else:
            raise ValueError('Method must be either GET or POST')

    async def _send_login_request(self):
        rsa_params = await self._fetch_rsa_params()
        if rsa_params is None:
            return None
        encrypted_password = await self._encrypt_password(rsa_params)
        rsa_timestamp = rsa_params['rsa_timestamp']
        request_data = await self._prepare_login_request_data(encrypted_password, rsa_timestamp)
        return await self._api_call('POST', 'IAuthenticationService', 'BeginAuthSessionViaCredentials',
                                    params=request_data)

    async def _check_for_captcha(self, login_response) -> None:
        if login_response.get('captcha_needed', False):
            raise Exception('Captcha required')

    async def _fetch_rsa_params(self, current_number_of_repetitions: int = 0):
        await self.session.post(SteamUrl.COMMUNITY_URL)
        request_data = {'account_name': self._username}
        response = await self._api_call('GET', 'IAuthenticationService', 'GetPasswordRSAPublicKey', params=request_data)

        if response.status == HTTPStatus.OK and 'response' in await response.json():
            key_data = await response.json()
            key_data = key_data['response']
            # Steam may return an empty 'response' value even if the status is 200
            if 'publickey_mod' in key_data and 'publickey_exp' in key_data and 'timestamp' in key_data:
                rsa_mod = int(key_data['publickey_mod'], 16)
                rsa_exp = int(key_data['publickey_exp'], 16)
                return {'rsa_key': PublicKey(rsa_mod, rsa_exp), 'rsa_timestamp': key_data['timestamp']}

        maximal_number_of_repetitions = 5
        if current_number_of_repetitions < maximal_number_of_repetitions:
            return await self._fetch_rsa_params(current_number_of_repetitions + 1)

        return None

    async def _encrypt_password(self, rsa_params) -> bytes:
        return b64encode(encrypt(self._password.encode('utf-8'), rsa_params['rsa_key']))

    async def _prepare_login_request_data(self, encrypted_password: bytes, rsa_timestamp: str) -> dict:
        return {
            'persistence': '1',
            'encrypted_password': encrypted_password,
            'account_name': self._username,
            'encryption_timestamp': rsa_timestamp,
        }

    async def _update_steam_guard(self, login_response) -> None:
        client_id = login_response['response']['client_id']
        steamid = login_response['response']['steamid']
        request_id = login_response['response']['request_id']
        code_type = 3
        code = await generate_one_time_code(self.shared_secret)

        update_data = {'client_id': client_id, 'steamid': steamid, 'code_type': code_type, 'code': code}
        await self._api_call(
            'POST', 'IAuthenticationService', 'UpdateAuthSessionWithSteamGuardCode', params=update_data
        )
        await self._pool_sessions_steam(client_id, request_id)

    async def _pool_sessions_steam(self, client_id: str, request_id: str) -> None:
        pool_data = {'client_id': client_id, 'request_id': request_id}
        response = await self._api_call('POST', 'IAuthenticationService', 'PollAuthSessionStatus', params=pool_data)
        response = await response.json()
        self.refresh_token = response['response']['refresh_token']

    async def _finalize_login(self):
        cookies = self.session.cookie_jar.filter_cookies(SteamUrl.COMMUNITY_URL)
        sessionid = cookies['sessionid'].value
        redir = f'{SteamUrl.COMMUNITY_URL}/login/home/?goto='
        finalized_data = {'nonce': self.refresh_token, 'sessionid': sessionid, 'redir': redir}
        headers = {'Referer': f'{SteamUrl.COMMUNITY_URL}/', 'Origin': SteamUrl.COMMUNITY_URL}
        response = await self.session.post(SteamUrl.LOGIN_URL + '/jwt/finalizelogin', headers=headers,
                                           data=finalized_data)
        return await response.json()

    async def _perform_redirects(self, response_dict) -> None:
        parameters = response_dict.get('transfer_info')
        if parameters is None:
            raise Exception('Cannot perform redirects after login, no parameters fetched')
        for pass_data in parameters:
            pass_data['params']['steamID'] = response_dict['steamID']
            await self.session.post(pass_data['url'], data=pass_data['params'])

    async def save_cookies(self, path_cookies: str = './cookies.json'):
        cookies = []
        for cookie in self.session.cookie_jar:
            cookies.append({
                'key': cookie.key,
                'value': cookie.value,
                'domain': cookie['domain'],
                'path': cookie['path'],
                'expires': cookie['expires'],
                'secure': cookie['secure'],
                'httponly': cookie['httponly']
            })
        async with aiofiles.open(path_cookies, 'w') as f:
            await f.write(json.dumps(cookies))

    async def load_cookies(self, path_cookies: str = './cookies.json'):
        try:
            async with aiofiles.open(path_cookies, 'r') as f:
                content = await f.read()
                cookies = json.loads(content)

                for cookie_data in cookies:                    #
                    domain = cookie_data['domain']
                    if not domain.startswith(('http://', 'https://')):
                        domain = f"https://{domain.lstrip('.')}"

                    url = URL(domain)

                    cookie = SimpleCookie()
                    cookie[cookie_data['key']] = cookie_data['value']

                    for attr in ['domain', 'path', 'expires', 'secure', 'httponly']:
                        if cookie_data.get(attr):
                            cookie[cookie_data['key']][attr] = cookie_data[attr]

                    self.session.cookie_jar.update_cookies(cookie, url)

            return self.session
        except FileNotFoundError:
            print("Cookie file not found. Proceeding without cookies.")
        except json.JSONDecodeError:
            print("Invalid JSON format in cookies file.")
        except KeyError as e:
            print(f"Missing key in cookie data: {e}")

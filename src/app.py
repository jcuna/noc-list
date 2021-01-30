"""
NOCLIST app

__author__ = 'Jon Garcia jcuna@joncuna.com'
"""

import hashlib
import json
import logging
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class RequestMaxTryReachedException(Exception):
    pass


class NoAuthException(Exception):
    pass


class HttpRequest:
    """
    HttpRequest wrapper for specific business
    """
    DEFAULT_REQUEST_HEADERS = {'Content-Type': 'application/json', 'Accept': 'text/html,application/json'}

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self._response_headers = {}
        self._response_body = ''
        self.code = 200
        self.succeeded = False
        self.headers = {}

    def set_headers(self, headers: dict):
        self.headers = headers

    def head(self, uri: str, extra_headers=None):
        """
        performs a HEAD request against endpoint
        :param extra_headers: dict extra headers to pass on request
        :param uri: str url resource path. Ensure you add trailing and leading slashes
        :raises URLError:
        """
        if extra_headers is None:
            extra_headers = {}
        resp = urlopen(self._build_request(uri, 'HEAD', extra_headers))
        self.code = resp.code
        self.succeeded = self.code < 400
        self._response_headers = dict(resp.headers)

    def get(self, uri, extra_headers=None):
        """
        performs a GET request against endpoint
        :param extra_headers: extra headers to pass on request
        :param uri: str url resource path. Ensure you add trailing and leading slashes
        :raises URLError:
        """
        if extra_headers is None:
            extra_headers = {}
        resp = urlopen(self._build_request(uri, 'GET', extra_headers))
        self.code = resp.code
        self.succeeded = self.code < 400
        self._response_headers = dict(resp.headers)
        self._response_body = resp.read().decode()

    def get_body(self) -> str:
        return self._response_body

    def get_headers(self) -> dict:
        return self._response_headers

    def _build_request(self, uri: str, method: str, headers):
        self.succeeded = False  # reset succeeded status on each request
        return Request(
            '{}{}'.format(
                self.base_url, uri),
            headers=dict(self.DEFAULT_REQUEST_HEADERS, **headers, **self.headers),
            method=method
        )


class ApiAuth:
    """
    An object to handle auth token storage and retrieval
    This should probably be a singleton, but `YAGNI`
    """
    CACHE_DIR = '/usr/data/cache/'
    CACHE_FILE = 'badsec_auth'

    _auth_token = None

    def __init__(self):
        if not os.path.exists(self.CACHE_DIR + self.CACHE_FILE):
            os.makedirs(self.CACHE_DIR, exist_ok=True)
            # creating file if not exists gives more flexibility over error handling.
            cache_file = open(self.CACHE_DIR + self.CACHE_FILE, 'w+')
            cache_file.close()

    def set_auth_token(self, auth_token: str):
        with open(self.CACHE_DIR + self.CACHE_FILE, 'w') as auth:
            self._auth_token = auth_token
            auth.write(auth_token)

    def get_auth_token(self) -> str:
        """
        First tries to get token from memory, then cache file

        :raises NoAuthException: If no auth_token available
        :return str: the auth_token
        """
        if self._auth_token:
            return self._auth_token
        with open(self.CACHE_DIR + self.CACHE_FILE, 'r') as auth:
            self._auth_token = auth.read()
        if self._auth_token:
            return self._auth_token

        raise NoAuthException('No authorization token available')

    def expire_token(self):
        self._auth_token = None
        cache_file = open(self.CACHE_DIR + self.CACHE_FILE, 'w+')
        cache_file.close()


class BadSecApiService:
    """
    Base class to wrap requests to the BADSEC server
    """
    base_url = os.environ.get('BADSEC_API')
    MAX_TRIES = 3

    def __init__(self):
        self.auth_service = ApiAuth()
        try:
            self.auth_service.get_auth_token()
        except NoAuthException as e:
            req = HttpRequest(self.base_url)
            self._auto_retry_request(req, '/auth', 'head')
            self.auth_service.set_auth_token(
                req.get_headers()['Badsec-Authentication-Token']
            )

    def get_from_server(self, path: str) -> list:
        """
        Performs get request to BADSEC server and serializes response to a python list
        :param path: str resource path
        :return: list a serialized list containing server's response
        """
        req = HttpRequest(self.base_url)
        req.set_headers({'Badsec-Authentication-Token': self.auth_service.get_auth_token()})
        req.set_headers({'X-Request-Checksum': hashlib.sha256(
            '{}{}'.format(self.auth_service.get_auth_token(), path).encode('utf8')
        ).hexdigest()})
        self._auto_retry_request(req, path)
        result = []
        for user in req.get_body().splitlines():
            result.append(user)
        return result

    def _auto_retry_request(self, request: HttpRequest, path: str, method: str = 'get'):
        """
        BadSec is not the most reliable server so we're covering our basis.

        :param request: Request
        :param path: str uri
        :raises RequestMaxTryReachedException
        """
        method = method.lower()
        if method not in ['get', 'head']:
            raise AttributeError('Invalid method')
        method_call = getattr(request, method)
        requests_count = 0
        while requests_count < self.MAX_TRIES:
            try:
                requests_count += 1
                method_call(path)
                if request.succeeded:
                    return
            except URLError:
                logger.exception('Error while performing a {} request to {}'.format(method, path))
                continue
        raise RequestMaxTryReachedException('Have exhausted max number of tries')


def print_noc_users():
    try:
        badsec = BadSecApiService()
        print(json.dumps(badsec.get_from_server('/users'), indent=4))
    except RequestMaxTryReachedException:
        logger.error('Tried to fetch data three times to no avail')
        exit(22)

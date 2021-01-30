"""
__author__ = 'Jon Garcia jcuna@joncuna.com'

Tests preparation lines. Run order is very important so injection happens correctly
"""

import io
import logging
import sys

exceptions = []

logger = logging.getLogger()
io_stream = io.StringIO()
logger.addHandler(logging.StreamHandler(io_stream))
logger.propagate = False

response = {'headers': {}, 'body': b'some important content\nmore content down here'}
payload = {}


class Mock(object):
    pass


def Request(*args, **kwargs):
    payload['args'] = args
    payload['kwargs'] = kwargs
    return payload


class AutoRetryTestSettings:
    set_auth_to_pass = False
    number_of_auth_requests = 0
    number_of_get_users_requests = 0


def urlopen(request):
    m = Mock()
    m.headers = response['headers']
    m.code = 200

    def read():
        return response['body']

    m.read = read

    if request['args'][0] == 'http://server.badsec.gov:8888/auth' and not AutoRetryTestSettings.set_auth_to_pass:
        AutoRetryTestSettings.number_of_auth_requests += 1
        raise URLError('request fails for some reason')
    elif request['args'][0] == 'http://server.badsec.gov:8888/auth' and AutoRetryTestSettings.set_auth_to_pass:
        m.headers = {'Badsec-Authentication-Token': 'looky me!, Im a hex not token'}
        m.code = 200
    elif request['args'][0] == 'http://server.badsec.gov:8888/users':
        AutoRetryTestSettings.number_of_get_users_requests += 1
        if AutoRetryTestSettings.number_of_get_users_requests < 3:
            raise URLError('request fails for some reason')
        m.code = 200

    return m


sys.modules['urllib.request'] = sys.modules[__name__]

"""
Tests start below
"""

import app
from app import *


def test_base_objects_exists():
    assert isinstance(getattr(app, 'HttpRequest'), object), 'HttpRequest object must exist'
    assert isinstance(getattr(app, 'ApiAuth'), object), 'ApiAuth object must exist'
    assert isinstance(getattr(app, 'BadSecApiService'), object), 'BadSecApiService object must exists'
    assert isinstance(getattr(app, 'print_noc_users'), object), 'print_noc_users object must exists'


def test_api_auth():
    auth = ApiAuth()
    try:
        auth.get_auth_token()
    except NoAuthException as e:
        exceptions.append(e)

    # assert that no auth tokens exists
    assert len(exceptions) == 1, 'A NoAuthException should be thrown when no token is available'

    auth.set_auth_token('some string')
    # assert that set token is returned properly
    assert auth.get_auth_token() == 'some string', '{} is not the expected token'.format(auth.get_auth_token())
    del auth

    # assert that token gets cached on file and retrieved from alternative class instances
    auth2 = ApiAuth()
    assert auth2.get_auth_token() == 'some string', '{} is not the expected token'.format(auth2.get_auth_token())

    # assert that new token replaces old
    auth2.set_auth_token('new token')
    del auth2
    auth3 = ApiAuth()
    assert auth3.get_auth_token() == 'new token', '{} is not the expected token'.format(auth3.get_auth_token())

    # assert that token is removed after calling expire method
    auth3.expire_token()
    try:
        auth3.get_auth_token()
    except NoAuthException as e:
        exceptions.append(e)
    assert len(exceptions) == 2


def test_api_service():
    req = HttpRequest('https://www.nowhere.com')
    req.set_headers({'first-header': 'a value'})
    req.head('/', extra_headers={'custom-header': 'ZibaSec'})
    # assert that url + path are in the request object
    assert payload['args'][0] == 'https://www.nowhere.com/', 'request was made to root path'
    # assert that headers added via set_headers method are present on request
    assert 'first-header' in payload['kwargs']['headers'], 'first header should be used to build request'
    # assert that custom headers are preserved in request object
    assert 'custom-header' in payload['kwargs']['headers'], 'custom header should be used to build request'
    # assert value of custom header matches arg
    assert payload['kwargs']['headers']['custom-header'] == 'ZibaSec', 'Custom header value should be ZibaSec'
    # assert default headers are still present
    assert 'Content-Type' in payload['kwargs']['headers'], 'Default headers should also be in request'
    # assert that default headers values are intact
    assert payload['kwargs']['headers']['Content-Type'] == 'application/json', 'Content type should be application/json'

    req = HttpRequest('https://www.nowhere.com')
    req.get('/users', extra_headers={'custom-header': 'ZibaSec'})
    assert isinstance(req.get_body(), str), 'RestRequest service should decode body to string'
    assert req.code


def test_bad_sec_api_service():
    # test that BADSEC api service will try at most 3 times to obtain a valid auth header before failing
    try:
        BadSecApiService()
    except RequestMaxTryReachedException as e:
        exceptions.append(e)
    assert AutoRetryTestSettings.number_of_auth_requests == 3, \
        '{} !eq 3. 3 is the max number of tries the service should have performed'.format(
            AutoRetryTestSettings.number_of_auth_requests
        )
    assert len(exceptions) == 3

    # assert api service responds properly upon a successful third and final attempt
    AutoRetryTestSettings.set_auth_to_pass = True  # modifies Mock object behaviors
    badsec = BadSecApiService()
    assert isinstance(badsec.auth_service, ApiAuth), 'badsec should have a valid auth service instantiated'
    resp = badsec.get_from_server('/users')
    assert AutoRetryTestSettings.number_of_get_users_requests == 3, \
        'Should have tried three times, fail first two and succeed last one'
    assert isinstance(resp, list), 'response should be a list of strings'


"""
Following section is just to run tests and better readability
"""


def print_failure(string: str):
    print('\x1b[1;31m{}\x1b[0m'.format(string))


def print_success(string: str):
    print('\x1b[1;32m{}\x1b[0m'.format(string))


def run_all_tests(mod):
    catch_all = None
    tests = 0
    failed = 0
    for member in dir(mod):
        if 'test_' in member:
            try:
                getattr(mod, member)()
            except AssertionError as err:
                print_failure('{}\n\t{}'.format(member, str(err)))
                failed += 1
            except Exception as ex:  # this is because I'm not using a test library. Only way to debug my actual tests
                catch_all = ex
            finally:
                tests += 1

    if failed > 0:
        # flush all captured logs from the app for debugging
        print('Captured logs...\n', file=sys.stderr)
        print(io_stream.getvalue(), file=sys.stderr)
        print('Summary:', file=sys.stderr)
        print_failure('{} tests failed and {} succeeded'.format(failed, tests - failed))
        if isinstance(catch_all, Exception):
            raise catch_all
        exit(22)
    else:
        print_success('{} tests succeeded'.format(tests))


run_all_tests(sys.modules[__name__])

from collections import namedtuple
import logging
import operator
import pprint
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import bs4
import execjs
import re
import requests
from slimit import ast
from slimit.parser import Parser
from slimit.visitors import nodevisitor

from helpers import lazy_property, script_from_script_tag, get_input_value_ided_as
from constants import BASIC_HEADERS, BEAUTIFULSOUP_PARSER

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


class LoginManager:
    """
    To login, just get the 'root_page_soup' property.  LoginManager will take care of getting a logged in session.

    The logged-in session is available on the session attribute.

    How Belgrade logins work in the browser
    =======================================
    1.  The user fills out access id in form at www.belgradestatebank.com and submits it.
    2.  Javascript POSTs the access id.  This code is located in:
        https://www.belgradestatebank.com/custom/belgradestatebank/javascript/global.js
    3.  The server redirects to a page which the user may not even see as it quickly gathers system stats and posts
        itself which then redirects to a security challenge page.

        The information-gathering page is at
        https://web9.secureinternetbank.com/pbi_pbi1961/pbi1961.ashx?wci=RemoteLogin&logonby=connect3&prmaccess=Account&rt=081908833
        The information-gathering scripts are at
        https://web9.secureinternetbank.com/pbi_pbi1961/pm_dp.js
        and
        https://web9.secureinternetbank.com/pbi_pbi1961/pm_fp.js

        pm_dp.js sets a global variable FPDONE to true after it sets form fields with system information
        and an inline script on the page then submits the form.
    4.  The page you are redirected to after that uses either Flash or, if not present, JS,
        to set window.location to the security challenge page.
    5.  When user submits the answer to the security challenge question, the browser is redirected to the password
        entry page.
    6.  When user submits the password form, javascript on the page uses RSA to encrypt the password with a key provided
        on the page, and the server then redirects to the accounts summary page and the user session is logged in.


    How we automate Belgrade logins
    ===============================
    1.  An url is parsed from a global.js file located at
        https://www.belgradestatebank.com/custom/belgradestatebank/javascript/global.js
    2.  The access id (username) is POSTed to that url.
    3.  Belgrade (really Fiserve) responds with a page that gathers information about your system with
        The purpose of this page is to collect system stats like display type, installed plugins, etc.
    4.  We ignore all of that, and just submit that form on that page.
    5.  After submitting that form we get the content of the security challenge page.
    6.  We parse that for the url to POST the security challenge response to as well as the question being asked
        for the security challenge.
    7.  We POST the security challenge response and receive the content of the password entry page.
    8.  We find the RSAEncrypt.js file via that pages source, download it, inject some custom JS into it, and then run
        it via an interpreter we find on the system.  This gives us our encrypted password.
    9.  We POST the encrypted password and get the root account page and an authenticated session.

    """
    sec_chall_referer = 'https://web9.secureinternetbank.com/pbi_pbi1961/pbi1961.ashx?wci=RemoteLogin&logonby=connect3&prmaccess=Account&rt=081908833'

    def __init__(self, raw_session: requests.Session, access_id: str, password: str, security_questions: tuple) -> None:
        self.session = raw_session
        self.access_id = access_id
        self.password = password
        self.security_questions = security_questions

    @lazy_property
    def root_page_soup(self) -> BeautifulSoup:
        """
        Lazily get the content of the root page.  This creates an authenticated session in self.session.

        A lazy property, meaning that the soup is only calculated/retrieved/parsed on first access.
        """
        modulus = get_input_value_ided_as(self._password_page_soup.body, 'Modulus')
        public_exp = get_input_value_ided_as(self._password_page_soup.body, 'PublicExponent')
        rsaiv = get_input_value_ided_as(self._password_page_soup.body, 'RSAIV')
        rid = get_input_value_ided_as(self._password_page_soup.body, 'RID')
        sptn = get_input_value_ided_as(self._password_page_soup.body.form, 'SPTN')

        rsa_encrypt_script_url = _get_RSAEncrypt_url(self._password_page_soup, self._access_id_post_url)

        # TODO: Figure out how to do this in python
        crypted_password = _rsa_encrypt(self.session,
                                        rsa_encrypt_script_url,
                                        modulus,
                                        public_exp,
                                        rsaiv,
                                        self.password)
        display_password = "*" * len(self.password)

        password_post_url = urljoin(self._access_id_post_url, self._password_page_soup.body.form['action'])
        assert "WCE=PasswordSubmit" in password_post_url, \
            "Unable to find accurate password POST url.  Found: {}".format(password_post_url)

        data = {
            "DisplayPassword": display_password,
            "Password": crypted_password,
            "RID": rid,
            "Submit": "Submit",
            "Modulus": modulus,
            "PublicExponent": public_exp,
            "RSAIV": rsaiv,
            "SPTN": sptn
        }

        headers = dict(BASIC_HEADERS)
        headers["Referer"] = self._security_challenge_post_url

        response = self.session.post(password_post_url, data=data, headers=headers)
        assert _is_root_page(response.text), "Unknown content received when expecting root account page."

        return BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

    @property
    def _auto_login_action_url(self) -> str:
        """ The url to post the autoLogin form data to."""

        assert self._auto_login_pre_post_soup.body.form.has_attr(
            'action'), "Unable to parse the autoLogin page prior to POSTing"

        return urljoin(self._access_id_post_url, self._auto_login_pre_post_soup.body.form['action'])

    @lazy_property
    def _pre_login_sptn(self) -> str:
        """The SPTN we post to self._auto_login_action_url.

        A lazy property, meaning we only do the search on the first access.
        """

        return self._auto_login_pre_post_soup.body.form.input['value']

    @lazy_property
    def _security_challenge_url(self) -> str:
        """Submits the autoLogin page so we can get the script containing the url to the security challenge page.

        A lazy property, meaning we only do the request/search/parsing on the first access.
        """
        logger.info('Handling autoLogin.')
        data = {"SPTN": self._pre_login_sptn}
        headers = dict(BASIC_HEADERS)
        headers['Referer'] = self.sec_chall_referer

        logger.debug('POSTing autologin to: %s', self._auto_login_action_url)
        logger.debug('POSTing autologin with headers: \n%s', pprint.pformat(headers))
        logger.debug('POSTing autologin data: \n%s', pprint.pformat(data))

        post1 = self.session.post(self._auto_login_action_url, data=data, headers=headers)
        assert post1.status_code == requests.codes.ok, \
            "Received status code {} when attempting to do autoLogin.".format(post1.status_code)

        sec_chall_script = script_from_script_tag(_find_redirect_script(post1.text))
        return urljoin(self._access_id_post_url, _parse_redirect_to_security_challenge_script(sec_chall_script))

    @lazy_property
    def _access_id_post_url(self) -> str:
        """Gets the URL to POST the access id to from the global.js script.

        A lazy property, meaning we only do the search on the first access.
        """
        logger.info('Parsing global.js from www.belgradestatebank.com for URL to POST access id to.')
        resp = requests.get("https://www.belgradestatebank.com/custom/belgradestatebank/javascript/global.js")
        assert resp.status_code == requests.codes.ok, "Unable to get URL for POSTing access_id."
        return _parse_global_js_for_access_id_action_url(resp.text)

    @lazy_property
    def _auto_login_pre_post_soup(self) -> BeautifulSoup:
        """
        Gets the soup for the page after submitting access id and
        before posting the autologin form on that page.

        A lazy property, meaning we only do the request/parsing on the first access.
        """
        logger.info('POSTing access id.')
        data = {"AccessID": self.access_id, "submit": "Submit"}

        headers = {
            "Host": urlparse(self._access_id_post_url).netloc,
            "Origin": "https://www.belgradestatebank.com",
            "Referer": "https://www.belgradestatebank.com"
        }

        response = self.session.post(self._access_id_post_url, data=data, headers=headers)
        return BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

    @lazy_property
    def _password_page_soup(self) -> BeautifulSoup:
        """ Gets the soup for the page where we enter the password.

        A lazy property, meaning we only do the request/parse on the first access.
        """
        data = {
            "QuestionAnswer": _find_security_question_answer(self._security_challenge_soup.body.text,
                                                             self.security_questions),
            "ChallengeType": get_input_value_ided_as(self._security_challenge_soup, "ChallengeType"),
            "MFARegister": 0,
            "RID": get_input_value_ided_as(self._security_challenge_soup, "RID"),
            "SecurityChallenge": get_input_value_ided_as(self._security_challenge_soup, "SecurityChallenge"),
            "Submit": "Submit",
            "SPTN": get_input_value_ided_as(self._security_challenge_soup, "SPTN")
        }

        response = self.session.post(self._security_challenge_post_url, data=data)
        assert response.status_code == requests.codes.ok, \
            "Failed to POST security challenge.  Received status: {}".format(response.status_code)

        return BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

    @lazy_property
    def _security_challenge_soup(self) -> BeautifulSoup:
        """ Gets the soup for the page where we answer the security challenge.

        A lazy property, meaning we only do the request/parse on the first access.
        """
        response = self.session.get(self._security_challenge_url)
        assert response.status_code == requests.codes.ok, \
            "Unable to get security challenge page.  Received status: {}".format(response.status_code)
        assert _is_security_challenge_page(response.text, self.security_questions), \
            "Server responded with invalid page when requesting security challenge page.  Page does not contain" \
            "any of our expected security questions."

        soup = BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

        assert soup.body.form.has_attr('action') and soup.body.form['action'], \
            "Security Challenge form does not have URL to submit to!"

        return soup

    @property
    def _security_challenge_post_url(self) -> str:
        """ The url we post the security challenge response to."""

        return urljoin(self._security_challenge_url, self._security_challenge_soup.body.form['action'])


def _find_redirect_script(page_text: str) -> bs4.Tag:
    """ Parses text for a script that sets window.location. """

    post_response_soup = BeautifulSoup(page_text, BEAUTIFULSOUP_PARSER)
    script = [script for script in post_response_soup.find_all('script') if
              script.string and 'window.location' in script.string]
    assert len(script) == 1, "Unable to find appropriate script tag to extract next URL from."

    return script[0]


def _parse_global_js_for_access_id_action_url(global_js: str) -> str:
    """ Parse global.js, provided as a string, for the url to post access id to. """
    parser = Parser()
    tree = parser.parse(global_js)

    parts = ['protocol', 'roDomain', 'ro', 'rt']
    UrlParts = namedtuple('UrlParts', parts)
    url_parts = UrlParts([], [], [], [])

    getvalue = operator.attrgetter('value')
    err = "Too many '{}' assignments in global.js."
    for node in nodevisitor.visit(tree):
        if isinstance(node, ast.Assign):
            try:
                left_value = getvalue(node.left).strip('\'"')
            except AttributeError:
                continue

            if left_value in parts:
                right_value = getvalue(node.right).strip('\'"')
                assert right_value not in getattr(url_parts, left_value), err.format('protocol')
                getattr(url_parts, left_value).append(right_value)

    return url_parts.protocol[0] + url_parts.roDomain[0] + url_parts.ro[0] + url_parts.rt[0]


def _parse_redirect_to_security_challenge_script(script: str) -> str:
    """ Parses the script which redirects us to security challenge page and gets that URL. """
    parser = Parser()
    tree = parser.parse(script)
    nodes = [node for node in nodevisitor.visit(tree) if isinstance(node, ast.Assign)]
    for node in nodevisitor.visit(tree):
        if isinstance(node, ast.Assign) and hasattr(node, 'left') and isinstance(node.left, ast.DotAccessor):
            children = node.left.children()
            if len(children) == 2 and children[0].value == 'window' and children[1].value == 'location':
                return node.right.value.strip('\'"')


def _is_security_challenge_page(page_text: str, security_questions: tuple) -> bool:
    """ Checks if any of our security challenge questions are in the provided text.  If so,
    assume is security challenge page. """

    for question, response in security_questions:
        if question in page_text:
            return True
    return False


def _find_security_question_answer(page_text: str, security_questions: tuple) -> str:
    """  Finds question in page text and returns answer. """
    for challenge, response in security_questions:
        if challenge in page_text:
            return response


def _rsa_encrypt(session: requests.Session, url: str, modulus: str, public_exp: str, rsaiv: str, pw: str):
    """ Hilariously runs the RSA javascript with some of our own javascript injected so that we can
    get the correct ciphertext for our password.

     Eventually need to switch to using a Python library once we figure out how to do that.
    """
    rsaencrypt_response = session.get(url)
    assert rsaencrypt_response.status_code == requests.codes.ok, \
        "Unable to get RSAEncrypt.js.  Status: {}\nBody:\n{}".format(rsaencrypt_response.status_code,
                                                                     rsaencrypt_response.text)

    assert "RSAKey" in rsaencrypt_response.text, "Got unexpected content for RSA encryption."

    script_additions = """
    var navigator = {};
    var window = {};
    window.crypto = null;

    function my_encrypt(modulus, publicExponent, rsaiv, password) {
        var rsa = new RSAKey();

        rsa.setPublic(modulus, publicExponent);

        return rsa.encrypt(rsaiv + password);
    }

    function MaskElement(elem) {}
    """

    new_script = script_additions + rsaencrypt_response.text

    ctx = execjs.compile(new_script)
    return ctx.call("my_encrypt", modulus, public_exp, rsaiv, pw)


def _get_RSAEncrypt_url(soup: BeautifulSoup, base_url: str) -> str:
    """ Finds the script tag pointing to `RSAEncrypt.js` and returns an absolute url for it. """
    script_tags = soup('script')
    for script_tag in script_tags:
        src = script_tag.get('src', '')
        if 'RSAEncrypt.js' in src:
            url = urljoin(base_url, src)
            return url

    assert False, "Unable to find RSAEncrypt script url on page."


def _is_root_page(page_text: str) -> bool:
    """ Tests if provided page_text is our root page...aka the account list page."""
    required_text = ["Log Off", "Your last login", "List Of Accounts", "Today.s Transactions",
                     "LandingPageWelcomeMessage"]
    for text in required_text:
        if not re.search(text, page_text, re.IGNORECASE):
            logger.debug("missing '{}' in root page text.".format(text))
            return False
    return True


def main():
    import keyring
    import json
    from constants import KEYRING_SERVICE_NAME, KEYRING_QUESTIONS_KEY, KEYRING_USERNAME_KEY

    security_questions = json.loads(keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_QUESTIONS_KEY))
    access_id = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME_KEY)
    password = keyring.get_password(KEYRING_SERVICE_NAME, access_id)

    l = LoginManager(requests.Session(), access_id, password, security_questions)
    rps = l.root_page_soup
    print(rps.body.option)
    return rps


if __name__ == '__main__':
    rps = main()

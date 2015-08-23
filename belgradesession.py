from collections import namedtuple
import logging
from pprint import pprint
import re
from decimal import Decimal
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import bs4
import requests

from account import Account
from helpers import lazy_property
from constants import BASE_URL, \
    ACCT_LIST_URL
from login import LoginManager

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())

ACCT_TEXT_REGEX = re.compile(r"(?P<acct_name>.*) (?P<acct_number>\d+) (?P<acct_bal>\$-?\d+\.\d\d)$")


class BelgradeSession:
    def __init__(self, access_id: str, password: str, security_questions: tuple) -> None:
        self.password = password
        self.access_id = access_id
        self.security_questions = security_questions

        self.login_manager = LoginManager(requests.Session(), self.access_id, self.password, self.security_questions)

    def get_sptn(self, url: str="") -> str:
        inputs = self._parsed_root_soup.select('input#SPTN')
        sptns = [i.get('value') for i in inputs]
        assert all([sptns[0] == s for s in sptns]), "{} contains conflicting SPTNs.".format(url or ACCT_LIST_URL)

        return sptns[0]

    @lazy_property
    def accounts(self) -> list:
        accounts = _parse_select_for_account_options(self._acct_select_soup)

        return [Account(self,
                        account_data.session_id,
                        account_data.name,
                        account_data.number,
                        account_data.balance) for account_data in accounts]

    @property
    def _parsed_root_soup(self) -> BeautifulSoup:
        return self.login_manager.root_page_soup

    @lazy_property
    def _acct_select_soup(self) -> bs4.Tag:
        select = self._parsed_root_soup.find(attrs={"class": "AccountListSelect"})
        assert select, "Unable to find select box for selecting accounts."

        return select

    @lazy_property
    def export_transactions_url(self) -> str:
        return urljoin(BASE_URL, self._parsed_root_soup.find('a', href=re.compile("WCI=Export"))['href'])

    def get_account(self, name: str="", number: str="") -> Account:
        for acct in self.accounts:
            if number and acct.number == number:
                return acct
            elif name and acct.name == name:
                return acct


AcctData = namedtuple('AcctData', ['name', 'number', 'balance', 'session_id'])


def _parse_select_for_account_options(select: BeautifulSoup) -> list:
    acct_options = []
    for option in select.find_all('option'):
        if not option.text:
            continue
        match = ACCT_TEXT_REGEX.match(option.text)
        assert match, "Invalid text to parse account data from: {}".format(option.text)
        balance = match.group('acct_bal')
        balance = balance.translate({ord('$'): None})

        acct_options.append(
            AcctData(match.group('acct_name'),
                     match.group('acct_number'),
                     Decimal(balance),
                     option['value']))

    return acct_options


if __name__ == '__main__':
    import keyring
    import json
    from constants import KEYRING_SERVICE_NAME, KEYRING_QUESTIONS_KEY, KEYRING_USERNAME_KEY

    SECURITY_QUESTIONS = json.loads(keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_QUESTIONS_KEY))
    ACCESS_ID = keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME_KEY)
    PASSWORD = keyring.get_password(KEYRING_SERVICE_NAME, ACCESS_ID)
    s = BelgradeSession(ACCESS_ID, PASSWORD, SECURITY_QUESTIONS)
    kc = s.get_account("Kasasa Checking")
    print(kc)

    rt = kc.recent_transactions
    pprint(rt)

import csv
import decimal
from io import StringIO
import logging
import os
from pprint import pformat
from urllib.parse import urljoin

from decimal import Decimal
import datetime
import arrow

from bs4 import BeautifulSoup
import requests

from helpers import set_query_parameter, get_input_value_ided_as, has_extension, replace_file_extension, \
    lazy_property, add_query_params
from constants import BASIC_HEADERS, BEAUTIFULSOUP_PARSER, BASE_URL

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


class Transaction:
    def __init__(self, account: 'Account', check_ref: str, amount: decimal.Decimal,
                 acct_balance: decimal.Decimal, date: arrow, description: str,
                 payee: str, category: str, pending: bool) -> None:
        self.account = account
        self.check_ref = check_ref
        self.amount = amount
        self.acct_balance = acct_balance
        self._date = date
        self.description = description
        self.payee = payee
        self.category = category
        self.pending = pending

    @property
    def date(self) -> arrow:
        return self._date.format('MM/DD/YYYY')

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return "Transaction(account='{0.account.name}', check_ref={0.check_ref}, amount={0.amount}, " \
               "acct_balance={0.acct_balance}, date={0.date}, description='{0.description}', " \
               "payee={0.payee}, category={0.category}, pending={0.pending})" \
            .format(self)

    def __add__(self, other) -> Decimal:
        if isinstance(other, Transaction):
            return self.amount + other.amount
        else:
            return self.amount + other

    def __radd__(self, other) -> Decimal:
        if other == 0:
            return self
        else:
            return self.__add__(other)


class Account:
    export_trans_url = urljoin(BASE_URL, "Pbi1961.ashx?WCI=TransMenu&WCE=Submit")

    def __init__(self, sess, acct_session_id: str, name: str, acct_number: str, balance: Decimal) -> None:
        # session_id is how the remote system identifies this account during this session
        self.acct_session_id = acct_session_id
        self.name = name
        self.balance = balance
        self.number = acct_number
        self._s = sess

        self._parsed_any_export_transactions_url = ""

    @property
    def _export_transactions_form_url(self) -> str:
        # Something like:
        # https://web9.secureinternetbank.com/pbi_pbi1961/PBI1961.ashx?SPTN=6CE501751BF0469E85EC8E561F3B3794&WCI=Export&WCE=&Number=FFF39798062A44E29BCD7BA17DEFF022
        return set_query_parameter(self._s.export_transactions_url, 'Number', self.acct_session_id)

    @property
    def _form_page_soup(self) -> BeautifulSoup:
        logger.info('GETing export transactions form page from: %s', self._export_transactions_form_url)
        response = self._s.login_manager.session.get(self._export_transactions_form_url)
        return BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

    def download_activity(self, from_date: datetime.date, to_date: datetime.date, cycle: int, format: str,
                          iif_account: str=None, to_file: str=None) -> requests.Response:

        iif_account = self.name if iif_account is None else iif_account

        data = _get_export_form_data(self._form_page_soup,
                                     self.acct_session_id,
                                     self._s.get_sptn(),
                                     from_date=from_date,
                                     to_date=to_date,
                                     format=format,
                                     cycle=cycle,
                                     iifaccount=iif_account)

        headers = dict(BASIC_HEADERS)
        headers["Referer"] = self._export_transactions_form_url

        logger.info('POSTing export transactions request to: %s', self.export_trans_url)
        logger.debug('POSTing export transactions request with headers:\n%s', pformat(headers))
        logger.debug('POSTing export transactions request with data:\n%s', pformat(data))

        result = self._s.login_manager.session.post(self.export_trans_url, data=data, headers=headers)

        if to_file is not None:
            if not has_extension(to_file):
                to_file = replace_file_extension(os.path.abspath(to_file), format)

            logger.info('Writing account activity to file: %s', to_file)

            with open(to_file, 'w', encoding=result.encoding) as f:
                f.write(result.text)

        return result

    def download_activity_from_date(self, from_date: datetime.date, format: str, iif_account: str=None,
                                    to_file: str=None) -> requests.Response:
        return self.download_activity(from_date, datetime.date.today(), 0, format, iif_account=iif_account,
                                      to_file=to_file)

    def download_recent_activity(self, format, iif_account: str=None, to_file: str=None):
        return self.download_activity(None, None, 1, format, iif_account=iif_account, to_file=to_file)

    @property
    def recent_transactions(self) -> list:
        recent = self.download_recent_activity('CSV')
        return csv_to_transactions(recent.text)

    @property
    def pending_transactions(self) -> list:
        return [t for t in self.get_page().recent_transactions if t.pending]

    def get_page(self) -> 'AccountPage':
        return AccountPage(self, self._s)

    def __repr__(self):
        return str(self)

    def __str__(self):
        u = "<Account name:'{}' bal:'{}' #:'{}'>"
        return u.format(self.name, self.balance, self.number)


class AccountPage:
    def __init__(self, account: Account, belgrade_session) -> None:
        self.account = account
        self._s = belgrade_session

    @property
    def page_url(self) -> str:
        params = {
            'SPTN': self._s.get_sptn(),
            'WCI': 'DdaDetail',
            'Number': self.account.acct_session_id
        }

        return add_query_params(BASE_URL, params)

    @lazy_property
    def soup(self) -> BeautifulSoup:
        logger.info('GETing account page soup from: %s', self.page_url)
        response = self._s.login_manager.session.get(self.page_url)
        return BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

    @property
    def sptn(self) -> str:
        return self.soup.body.find('input', id='SPTN')['value']

    @property
    def txt_guid(self) -> str:
        return self.soup.body.find('input', id='txtGuid')['value']

    @property
    def recent_trans_ajax_url(self) -> str:
        query_params = {
            "WCI": "AJAX",
            "WCE": "GetData",
            "Request": "Trans",
            "SPTN": self.sptn,
            "GUID": self.txt_guid,
            "Cycle": "01",
            "NumOfTrans": "-1",
            "id": 12345  # just a random number
        }

        return add_query_params(BASE_URL, query_params)

    @property
    def _recent_trans_soup(self) -> BeautifulSoup:
        response = self._s.login_manager.session.get(self.recent_trans_ajax_url)
        return BeautifulSoup(response.text, BEAUTIFULSOUP_PARSER)

    @lazy_property
    def recent_transactions(self) -> list:
        table = self._recent_trans_soup.find('table', attrs={'class': 'DataTable', 'id': 'trnTable'})
        assert table, "Unable to find table of recent transactions."

        rows = table.find_all('tr')
        transactions = []
        for row in rows:
            cols = row.find_all('td')

            if len(cols) != 7:
                # This is likely the row with the select to choose number of transactions.
                continue

            data = [col.text.strip() for col in cols]
            date = data[0]
            check_ref = data[1]
            description = data[2]
            debit = -Decimal(data[3]) if data[3] else Decimal(0)
            credit = Decimal(data[4]) if data[4] else Decimal(0)
            balance = Decimal(data[5])

            transactions.append(
                Transaction(account=self.account,
                            check_ref=check_ref,
                            amount=debit + credit,
                            acct_balance=balance,
                            date=arrow.get(date.strip("*"), 'MM/DD/YYYY'),
                            description=description,
                            payee='',
                            category='',
                            pending=date.startswith("*"))
            )
        return transactions

def csv_to_transactions(data: str) -> list:
    headers = ['Account', 'ChkRef', 'Debit', 'Credit', 'Balance', 'Date', 'Description', 'Payee', 'Category']

    reader = csv.reader(StringIO(data), delimiter=',')

    transactions = []
    for row in reader:
        if row == headers:
            continue
        assert len(row) == 7, "Cannot parse {} into a Transaction.".format(row)
        transactions.append(Transaction(*[d.strip() for d in row]))
    return transactions

def _get_export_form_data(form_page_soup: BeautifulSoup,
                          acct_session_id: str,
                          sptn: str,
                          from_date: datetime.date=None,
                          to_date: datetime.date=None,
                          format: str='OFX',
                          cycle: int=0,
                          iifaccount: str='') -> dict:
    """
    Returns dict for POSTing to download transactions.

    :param form_page_soup: The soup of the page to extract fields from.
    :param acct_session_id: The per-session account number or id.
    :param sptn: The per-session identifier.
    :param from_date: The starting date to download transactions from.  Only valid when `cycle` is 0.
    :param to_date: The ending date to download transactions to.  Only valid when `cycle` is 0. Defaults to today.
    :param format: One of ['QFX', 'QIF', 'QBO', 'IIF', 'OFX', 'CSV'].  If IIF, must provide `iifaccount`.
    :param cycle: One of [0, 1, 2, 3].  If 0, must provide `from_date` and optionally `to_date`.
        '1' is for recent transactions, '2' is for current statement, and 3 is for previous statement.
    :param iifaccount: The name of the Quickbooks account if downloading IIF format.
    :return: dict of POSTable data.
    """
    assert -1 < cycle < 4, "Cycle must be between -1 and 4."
    if cycle == 0:
        if not to_date:
            to_date = datetime.date.today()
        assert from_date <= to_date, "You must provide a from_date lower than a to_date."
        from_date = from_date.strftime('%m/%d/%y')
        to_date = to_date.strftime('%m/%d/%y')
    else:
        from_date = None
        to_date = None

    valid_formats = ['QFX', 'QIF', 'QBO', 'IIF', 'OFX', 'CSV']
    assert format in valid_formats, '{} is an invalid format.  It must be one of: {}'.format(format, valid_formats)
    if format == 'IIF':
        assert iifaccount, "You must provide an account name for Quickbooks when downloading to IIF."

    return {
        'Cycle': '0{}'.format(cycle),
        'Tran_Type': '09',  # This seems to always be this number
        'FromDate': from_date,
        'ThruDate': to_date,
        'lstFormat': format,
        'Submit': 'Export',
        'IIFAccount': get_input_value_ided_as(form_page_soup, 'IIFAccount'),
        'WO': get_input_value_ided_as(form_page_soup, 'WO'),
        'ESPTN': get_input_value_ided_as(form_page_soup, 'ESPTN'),
        'Number': acct_session_id,
        'Type': '001',  # This seems to always be this number,
        'SPTN': sptn,
    }

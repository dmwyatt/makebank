import os
from urllib.parse import urljoin
from decimal import Decimal
import datetime

from bs4 import BeautifulSoup
import requests

from helpers import set_query_parameter, BASE_URL, BASIC_HEADERS, BEAUTIFULSOUP_PARSER, get_input_value_ided_as


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
    def export_transactions_form_url(self):
        # Something like:
        # https://web9.secureinternetbank.com/pbi_pbi1961/PBI1961.ashx?SPTN=6CE501751BF0469E85EC8E561F3B3794&WCI=Export&WCE=&Number=FFF39798062A44E29BCD7BA17DEFF022
        return set_query_parameter(self._s.export_transactions_url, 'Number', self.acct_session_id)

    def download_activity(self, from_date: datetime.date, to_date: datetime.date, to_file: str=''):
        form_page = self._s.login_manager.session.get(self.export_transactions_form_url)
        form_page_soup = BeautifulSoup(form_page.text, BEAUTIFULSOUP_PARSER)

        data = {
            'Cycle': '00',  # TODO: Don't hardcode this
            'Tran_Type': '09',  # This seems to always be this number
            'FromDate': from_date.strftime('%m/%d/%y'),
            'ThruDate': to_date.strftime('%m/%d/%y'),
            'lstFormat': 'QFX',  # TODO: Don't hardcode this
            'Submit': 'Export',
            'IIFAccount': None,  # TODO: Don't hardcode this
            'WO': 1,  # Don't know...
            'ESPTN': get_input_value_ided_as(form_page_soup, 'ESPTN'),
            'Number': self.acct_session_id,
            'Type': '001',  # This seems to always be this number,
            'SPTN': self._s.get_sptn(),
        }

        headers = dict(BASIC_HEADERS)
        headers["Referer"] = self.export_transactions_form_url

        result = self._s.login_manager.session.post(self.export_trans_url, data=data, headers=headers)
        if to_file:
            with open(os.path.abspath(to_file), 'w') as f:
                f.write(result.text)
        return result

    def __repr__(self):
        return str(self)

    def __str__(self):
        u = "<Account name:'{}' bal:'{}' #:'{}'>"
        return u.format(self.name, self.balance, self.number)

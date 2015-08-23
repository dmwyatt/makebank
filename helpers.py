import ast
from collections import namedtuple
import operator
import os
from urllib.parse import urlsplit, urlencode, urlunsplit, parse_qs
import re

import bs4
import requests
from slimit.parser import Parser
from slimit.visitors import nodevisitor


class lazy_property:
    """http://stackoverflow.com/questions/3012421/python-lazy-property-decorator"""

    def __init__(self, fget):
        self.fget = fget
        self.func_name = fget.__name__

    def __get__(self, obj, cls):
        # accessing class variable doesn't make sense for a property
        if obj is None:
            # and that's what obj=None means
            return None

        # Here we do the actual expensive part
        value = self.fget(obj)

        # And then we just replace the method with its computed value
        setattr(obj, self.func_name, value)

        return value


def get_input_value_ided_as(page_soup: bs4.BeautifulSoup, _id: str) -> str:
    results = page_soup.find_all('input', id=_id)
    if len(results) > 1:
        values = [result.attrs.get('value') for result in results]
        if all([value == values[0] for value in values]):
            return values[0]

    assert len(results) == 1, "Total fields id'ed as '{}': {}.  Expected one.".format(_id, len(results))
    assert results[0].has_attr('value'), "Input does not have a value."
    return results[0]['value']


_access_id_url = ""


def get_access_id_url():
    global _access_id_url
    if not _access_id_url:
        resp = requests.get("https://www.belgradestatebank.com/custom/belgradestatebank/javascript/global.js")

        assert resp.status_code == requests.codes.ok, "Unable to get URL for POSTing access_id."

        _access_id_url = parse_global_js_for_access_id_action_url(resp.text)
    return _access_id_url


def parse_global_js_for_access_id_action_url(global_js):
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


def set_query_parameter(url: str, param_name: str, param_value: str, remove_existing=False) -> str:
    """Given a URL, set or replace a query parameter and return the
    modified URL.

    >>> set_query_parameter('http://example.com?foo=bar&biz=baz', 'foo', 'stuff')
    'http://example.com?foo=stuff&biz=baz'

    """
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    query_params = parse_qs(query_string) if not remove_existing else {}

    query_params[param_name] = [param_value]
    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment))


def remove_query_parameters(url: str) -> str:
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    return urlunsplit((scheme, netloc, path, {}, fragment))


def add_query_params(url: str, params: dict, remove_existing=False) -> str:
    scheme, netloc, path, query_string, fragment = urlsplit(url)

    query_params = parse_qs(query_string) if not remove_existing else {}

    query_params.update(params)
    new_query_string = urlencode(query_params, doseq=True)

    return urlunsplit((scheme, netloc, path, new_query_string, fragment))


def script_from_script_tag(script_tag: bs4.Tag):
    raw = script_tag.string
    if not raw:
        return

    return raw.strip().replace("<!--", "").replace("-->", "").strip()


def replace_file_extension(path: str, new_ext: str):
    new_ext = re.sub('^\.*', '', new_ext)
    return os.path.splitext(path)[0] + '.' + new_ext


def has_extension(path: str):
    return bool(os.path.splitext(path)[1])

# -*- coding: utf-8 -*-
# created by restran on 2019/05/31
from __future__ import unicode_literals, absolute_import

import hashlib
import os
import string
import uuid
from collections import deque
from optparse import OptionParser

from bs4 import BeautifulSoup
from future.moves.urllib.parse import urlunparse, urlparse, urljoin, quote, unquote
from mountains import logging
from mountains import text_type
from mountains.http import random_agent
from mountains.logging import ColorStreamHandler
from mountains.tornado import async_request
from tornado import gen, ioloop
from tornado.escape import native_str
from tornado.gen import Return
from tornado.httpclient import HTTPError

logging.init_log(ColorStreamHandler(logging.INFO,
                                    '[%(asctime)s] %(message)s',
                                    logging.DATE_FMT_SIMPLE))

logger = logging.getLogger(__name__)

parser = OptionParser()
parser.add_option("-u", "--url", dest="target_url", type="string",
                  help="target url, e.g. http://127.0.0.1:8080/index.php")
parser.add_option("-w", "--worker", dest="worker_num", type="int",
                  default=5, help="max worker num")
parser.add_option("-t", "--timeout", dest="timeout", type="int",
                  default=3, help="timeout in seconds")
parser.add_option("-v", dest="verbose", action="store_true",
                  default=False, help="verbose log")
parser.add_option("-c", dest="cookies", default=None, help='set cookies, e.g. -c "a=1; b=2"')
parser.add_option("-H", "--headers", dest="headers", default=None, action="append",
                  help='http header; e.g. -H "X-Forwarder-For: 127.0.0.1" -H "Host: www.example.com"')
parser.add_option("-s", "--same_site", dest="same_site", default=False,
                  action="store_true", help="download same site url")


class AsyncHTTPExecutor(object):
    """
    异步HTTP请求，可以并发访问
    """

    def __init__(self, base_url, max_workers=10, connect_timeout=10, request_timeout=100,
                 cookies=None, verbose=False, headers=None,
                 same_site=False, ):
        self.base_url = base_url
        self.base_url_netloc = urlparse(base_url).netloc
        self.task_queue = deque()
        self.task_queue.append(base_url)
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.cookies = cookies
        self.headers = headers
        self.file_md5_dict = {}
        self.scan_url_dict = {}

        self.same_site = same_site

    def get_next_task(self):
        try:
            return self.task_queue.popleft()
        except IndexError:
            return None

    def make_url(self, item):
        url_parsed = urlparse(item)
        if url_parsed.scheme != '':
            return item
        else:
            if item.startswith('/'):
                item = item.lstrip('/')
            item = item

            new_item = []
            for c in item:
                if c not in string.printable[:-6]:
                    c = quote(c)
                new_item.append(c)
            item = ''.join(new_item)
            url = urljoin(self.base_url, item)
            native_str(url)
            return url

    def process_html(self, current_url, response):
        if response.body in (None, b'', ''):
            return

        content_type = response.headers.get('Content-Type', '')
        if 'text/html' in content_type.lower():
            soup = BeautifulSoup(response.body, 'html5lib')
            script_list = [t.get('src') for t in soup.find_all('script')]
            style_list = [t.get('href') for t in soup.find_all('link')]
            a_list = [t.get('href') for t in soup.find_all('a')]
            script_style_list = script_list + style_list
            script_style_list = set([t for t in script_style_list if t is not None])
            a_list = set([t for t in a_list if t is not None])

            new_a_list = []
            for t in a_list:
                if t.startswith('#'):
                    continue

                # apache 目录列出，排序的链接
                if t in (
                        '?C=N;O=A', '?C=N;O=D', '?C=M;O=A', '?C=M;O=D',
                        '?C=D;O=A', '?C=D;O=D', '?C=S;O=A', '?C=S;O=D'):
                    continue

                url = urljoin(current_url, t)
                url_parsed = urlparse(url)
                if url_parsed.scheme in ('http', 'https'):
                    url = urlunparse((url_parsed.scheme, url_parsed.netloc,
                                      url_parsed.path, '', url_parsed.query, ''))
                    new_a_list.append(url)

            a_list = set(new_a_list)
            for t in script_style_list:
                url = urljoin(current_url, t)
                self.task_queue.append(url)
                # 测试 Webpack 的 sourcemap 文件
                if (t.endswith('.js') or t.endswith('.css')) and not t.endswith('.map'):
                    self.task_queue.appendleft(url + '.map')
            for url in a_list:
                self.task_queue.appendleft(url)

    def save_file(self, url_parsed, res):
        try:
            md5 = hashlib.md5(res.body).hexdigest()
            netloc = url_parsed.netloc
            site_dir_name = netloc.replace('.', '_').replace(':', '_')
            if url_parsed.path == '':
                path = site_dir_name + '/'
            else:
                path = site_dir_name + url_parsed.path
            path = unquote(path)
            if path.endswith('/'):
                path = path + 'index.html'
            dir_name = os.path.dirname(path)

            if md5 in self.file_md5_dict and self.file_md5_dict[md5] == path:
                return

            logger.warning('saved: {}'.format(path))
            # 相同目录下文件夹名不能跟文件名一样，因为无法保存，需要改名
            if os.path.exists(path) and os.path.isdir(path):
                path = path + '_' + str(uuid.uuid4())[-3:]
            elif os.path.exists(dir_name) and os.path.isfile(dir_name):
                dir_name = dir_name + '_' + str(uuid.uuid4())[-3:]
                path = dir_name + path.split('/')[-1]

            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
            with open(path, 'wb') as f:
                f.write(res.body)

            self.file_md5_dict[md5] = path
        except Exception as e:
            logger.error(e)
            pass

    @gen.coroutine
    def do_request(self, item):
        logger.info('request: {}'.format(item))

        url = self.make_url(item)
        if url in self.scan_url_dict:
            return
        else:
            self.scan_url_dict[url] = None

        headers = {
            "User-Agent": random_agent()
        }

        if self.headers is not None:
            headers.update(self.headers)

        if self.cookies is not None:
            headers['Cookie'] = self.cookies

        @gen.coroutine
        def on_response(res):
            """
            :rtype res HTTPResponse
            :param res:
            :return:
            """
            if res.code == 200:
                try:
                    url_parsed = urlparse(url)
                    self.save_file(url_parsed, res)
                    if url_parsed.netloc == self.base_url_netloc or self.same_site:
                        self.process_html(url, res)
                except Return:
                    pass
                except Exception as e:
                    logger.error(e)
            elif res.code in (301, 302):
                location = res.headers.get('Location')
                redirect_url = urljoin(url, location)
                self.task_queue.appendleft(redirect_url)

        def on_error(e):
            # logger.exception(e)
            if not isinstance(e, HTTPError) or self.verbose:
                msg = text_type(e)
                logger.error('Exception: %s %s %s' % (msg, method, item))

        method = 'GET'
        yield async_request(method, url, headers=headers,
                            on_response=on_response, on_error=on_error)

    @gen.coroutine
    def fetch_url(self):
        item = self.get_next_task()
        if self.verbose:
            logger.info(item)

        while item is not None:
            try:
                yield self.do_request(item)
                item = self.get_next_task()
            except Exception as e:
                if self.verbose:
                    logger.exception(e)

    @gen.coroutine
    def run(self):
        yield self.fetch_url()
        yield [self.fetch_url() for _ in range(self.max_workers)]


class WebGet(object):
    def __init__(self, url, worker_num=10,
                 cookies=None, headers=None,
                 same_site=False, verbose=False):
        self.site_lang = ''
        self.raw_base_url = url
        self.base_url = url
        self.worker_num = worker_num
        self.cookies = cookies
        self.verbose = verbose
        self.same_site = same_site

        # 设置 headers
        if headers is not None and isinstance(headers, list):
            new_headers = {}
            for t in headers:
                try:
                    x = t.split(':')
                    new_headers[x[0].strip()] = x[1].strip()
                except Exception as e:
                    logger.error('Invalid Header: %s, %s' % (t, e))
            headers = new_headers

        self.headers = headers
        self.first_item = ''
        self.dict_data = {}
        self.first_queue = []

    @gen.coroutine
    def run(self):
        executor = AsyncHTTPExecutor(
            self.base_url,
            self.worker_num,
            cookies=self.cookies,
            headers=self.headers,
            same_site=self.same_site,
            verbose=self.verbose
        )
        yield executor.run()


@gen.coroutine
def main():
    (options, args) = parser.parse_args()
    if options.target_url is None:
        parser.print_help()
        return

    logger.info('Target url: %s' % options.target_url)
    logger.info('Worker num: %s' % options.worker_num)
    if options.cookies is not None:
        logger.info('Cookies: %s' % options.cookies)

    if options.same_site is True:
        # 对于页面中的链接，不再主动去访问探测
        logger.info('Same site')

    ws = WebGet(options.target_url,
                options.worker_num,
                options.cookies,
                options.headers,
                options.same_site,
                options.verbose)
    yield ws.run()


if __name__ == '__main__':
    io_loop = ioloop.IOLoop.current()
    io_loop.run_sync(main)

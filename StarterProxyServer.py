import os
import platform
import sys
import getopt
import subprocess
import ourlogging
import time

# Стартер предназнчен для запуска модуля ProxyServer в трех разных режимах
# Для удобства интеграции с интерфесом, для подключения кнопок "СТАРТ", "СТОП"

gVersion = "0.1"

script_path = os.path.dirname(os.path.realpath(__file__))
#devnull = open('/dev/null', 'w')

# Для лога running
if platform.platform().startswith('Windows'):
    logging_running = ourlogging.Logging(os.path.join(os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH'), 'proxyserver.running'))
else:
    logging_running = ourlogging.Logging(os.path.join(os.getenv('HOME'), 'proxyserver.running'))

def usage():
    print("\nProxyServer " + gVersion + " by ActionNum")
    print("Назначение: StarterProxyServer <параметры>\n")
    print("Параметры:")
    print("-m, --mode= Режим запуска прокси сервера.\
            1. None      Сбор статистики - режим по умолчанию, если запускать без параметров;\
            2. jsinj     JavaScript Injection - режим внедрения JavaScript в браузер клиента;\
            3. sslstrip  SSL Strip - понижение протокола с HTTPS до HTTP, позволяет перехватывать авторизационные данные")
    print("-h                                Print this help message.")
    print("")


def parse_options(argv):

    try:
        mode = None
        opts, args = getopt.getopt(argv, "hw:l:psafk",
                                   ["help", "mode="])

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-m", "--mode"):
                mode = arg

        return mode

    except getopt.GetoptError:
        usage()
        sys.exit(2)


def main(argv):

    mode = parse_options(argv)

    if mode == 'jsinj':
        # os.system()
        pass
    elif mode == 'sslstrip':
        # Start Moxi SSL Strip + with dnsserver
        pass
    else:
        # Старт в режиме "Сбора статистики"
        try:
            child_proc = subprocess.Popen(["python", os.path.join(script_path, 'scr', 'ProxyServer.py'), "-p 8080"],\
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            logging_running.write_log('PROXY SERVER', 'Успешно запущен с PID = ' + str(child_proc.pid))
            return child_proc
        except Exception as e:
            print(e)
            logging_running.write_log('ОШИБКА', 'Ну удалось запустить Proxy Server')
            sys.exit()


def stop(child_proc):
    child_proc.kill()
    logging_running.write_log('СТОП', 'Proxy Server завершил свою работу')
    sys.exit(0)


if __name__ == '__main__':
    print("debug")
    child_proc = main(sys.argv[1:])
    print(child_proc.pid)
    time.sleep(15)
    stop(child_proc)

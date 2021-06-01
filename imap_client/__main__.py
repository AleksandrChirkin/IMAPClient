from argparse import ArgumentParser
from imap_client import IMAPClient, IMAPError
from socket import gaierror, timeout
from typing import Any, Dict


def parse_args() -> Dict[str, Any]:
    parser = ArgumentParser()
    parser.add_argument('--ssl', action='store_true',
                        help='Use SSL connection')
    parser.add_argument('-s', '--server', default='imap.mail.ru:143',
                        help='Server and port')
    parser.add_argument('-n', nargs='*', default=['-1'],
                        help='Number (interval) of letters')
    parser.add_argument('-u', '--user', help='User name')
    return parser.parse_args().__dict__


if __name__ == '__main__':
    try:
        IMAPClient(**parse_args()).run()
    except (IMAPError, ValueError) as e:
        print(e)
        exit(1)
    except gaierror:
        print('Failed to connect server (DNS Error)')
        exit(1)
    except timeout:
        print('Failed to get response from server')
        exit(1)
    except KeyboardInterrupt:
        print('Terminated.\n')
        exit()

from imap_client import IMAPError
from socket import AF_INET, SOCK_STREAM, gaierror, socket, timeout
from threading import Lock
from typing import List
import base64
import getpass
import ssl


class IMAPClient:
    def __init__(self, ssl: bool, server: str, n: List[str], user: str):
        self.ssl = ssl
        server_port = server.split(':')
        if len(server_port) != 2:
            raise ValueError('Incorrect address '
                             '(must be in "server:port" format)')
        self.server = server_port[0]
        self.port = int(server_port[1])
        if len(n) == 0 or len(n) > 2 or len(n) == 2 and\
                (int(n[0]) > int(n[1]) or int(n[0]) < 0 or int(n[1]) < 0):
            raise ValueError('Incorrect letter interval')
        self.interval = n
        self.user = user
        self.name = 'A001'
        self.print_lock = Lock()

    @staticmethod
    def receive_message(sock: socket) -> str:
        data = bytearray()
        try:
            while True:
                received_data = sock.recv(1024)
                data.extend(received_data)
                if len(received_data) < 1024:
                    break
        except timeout:
            pass
        finally:
            return data.decode('utf-8')

    @staticmethod
    def send_message(sock: socket, msg: str) -> None:
        sock.send(msg.encode('utf-8'))

    def modify_login_and_password(self) -> str:
        return base64.b64encode(f'{self.user}{getpass.getpass()}'
                                .encode('utf-8')).decode('utf-8')

    @staticmethod
    def get_addr(addr_str: List[str]) -> str:
        source_name = addr_str[0]
        if source_name[1:11] == '=?utf-8?B?':
            source_name = base64.b64decode(source_name[11:-1]) \
                .decode('utf-8')
        else:
            source_name = ' '.join(addr_str
                                   [:addr_str.index("NIL")])[1:-1] \
                if "NIL" in addr_str else ''
        return f'{addr_str[-2][1:-1]}@{addr_str[-1][1:-1]} ' \
               f'<{source_name}>'

    def run(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.connect((self.server, self.port))
            sock.settimeout(1)
            try:
                self.receive_message(sock)
            except timeout:
                raise gaierror
            if self.ssl:
                self.send_message(sock, f'{self.name} STARTTLS\n')
                self.receive_message(sock)
                sock = ssl.wrap_socket(sock)
            else:
                print('WARNING! You are in open connection, '
                      'so your data could be compromised!')
            self.send_message(sock, f'{self.name} LOGIN '
                                    f'{self.user} '
                                    f'{getpass.getpass()}\n')
            login_response = self.receive_message(sock)
            if 'NO' in login_response:
                raise IMAPError(login_response[5:])
            self.send_message(sock, f'{self.name} LIST \"\" *\n')
            list_response = self.receive_message(sock)
            folders = [f[f.find('/')+4:-2]
                       for f in list_response.split('\n')[:-1]]
            for folder in folders[:-1]:
                self.select_group(sock, folder)

    def select_group(self, sock: socket, folder: str) -> None:
        number_str = ''
        while 'EXISTS' not in number_str:
            self.send_message(sock, f'{self.name} SELECT {folder}\n')
            number_str = self.receive_message(sock).split('\n')[1]
        print(f'{folder} FOLDER')
        letters_number = int(number_str.split(' ')[1])
        letter_range = range(letters_number) if self.interval == ['-1'] else (
            range(min(letters_number, int(self.interval[0])))
            if len(self.interval) == 1
            else range(int(self.interval[0]), int(self.interval[1]) + 1)
        )
        for i in letter_range:
            self.send_message(sock, f'{self.name} FETCH {i} '
                                    f'(FLAGS FULL)\n')
            headers = self.receive_message(sock)
            if not headers or '(nothing matched)' in headers:
                break
            self.get_headers(headers)
            self.get_body(headers)
        print()

    def get_headers(self, headers: str) -> None:
        date_str = headers[headers.find("INTERNALDATE") + 14:]
        date = date_str[:date_str.find('"')]
        size_str = headers[headers.find("RFC822.SIZE") + 12:]
        size = size_str[:size_str.find(' ')]
        envelope = headers[headers.find("ENVELOPE") + 9:
                           headers.find('BODY') - 1]
        subj_str = envelope[36:] if envelope[35:38] != 'NIL' \
            else "- "
        subj = subj_str[:subj_str.find('"')]
        if subj[:10] == '=?utf-8?B?':
            subj = base64.b64decode(subj[10:]).decode('utf-8')
        subj = subj.replace('\n', '\\n')
        from_str = envelope[envelope.find('((') + 2:
                            envelope.find('))')].split(' ')
        from_addr = self.get_addr(from_str)
        to_str = envelope[envelope.rfind('((') + 2:
                          envelope.rfind('))')].split(' ')
        to_addr = self.get_addr(to_str)
        print(f'To: {to_addr} From: {from_addr} Subject: {subj} '
              f'{date} Size:{size}')

    @staticmethod
    def get_body(headers: str) -> None:
        body = headers[headers.find('BODY') + 7:headers.rfind(')')]
        body_parts = body.split(')(')
        attaches = []
        for part in body_parts:
            if part.find("name") == -1:
                continue
            name = part[part.find("name") + 7:part.find('")')]
            encoding = '"base64"' if '"base64"' in part \
                else '"8bit"'
            attach_size = int(part[part.find(encoding) + 9:]
                              .split(' ')[0].replace(')', ''))
            attaches.append((name, attach_size))
        print(f'{len(attaches)} attaches: {attaches}')

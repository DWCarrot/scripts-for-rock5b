##############################################
# Usage:
# python notify_ip.py <cache_file> <smtp_host> <smtp_email_sender> <smtp_password> <smtp_email_reciever> [timeout_ms]
#   <cache_file>: file to store the last IP address
#   <smtp_host>: SMTP host (and port optional)  e.g. smtp.gmail.com:465 or smtp.gmail.com
#   <smtp_email_sender>: email address of the sender
#   <smtp_password>: smtp token of the sender
#   <smtp_email_reciever>: email address of the receiver
#   [timeout_ms]: timeout in milliseconds; optional
##############################################

from http.client import HTTPSConnection, HTTPResponse
from typing import List, Tuple
from urllib.parse import urlparse
from platform import python_version
from enum import Enum
import socket
import json
from ipaddress import ip_address, IPv4Address, IPv6Address
from smtplib import SMTP_SSL
from email.message import EmailMessage
import sys


class IPInfo:


    class AddressFamily(Enum):
        IPv4 = "ipv4"
        IPv6 = "ipv6"


    USER_AGENT = "Python-urllib/%s" % python_version()

    ipv4: IPv4Address | None
    ipv4_remote: str | None
    ipv6: IPv6Address | None
    ipv6_remote: str | None
    primary: AddressFamily | None

    def __init__(self, **kwargs):
        ipv4 = kwargs.get("ipv4")
        if ipv4 is not None:
            ipv4 = ip_address(ipv4)
            if not isinstance(ipv4, IPv4Address):
                raise ValueError("ipv4 is not a valid IPv4 address")
        self.ipv4 = ipv4
        self.ipv4_remote = kwargs.get("ipv4_remote")
        ipv6 = kwargs.get("ipv6")
        if ipv6 is not None:
            ipv6 = ip_address(ipv6)
            if not isinstance(ipv6, IPv6Address):
                raise ValueError("ipv6 is not a valid IPv6 address")
        self.ipv6 = ipv6
        self.ipv6_remote = kwargs.get("ipv6_remote")
        primary = kwargs.get("primary")
        self.primary = IPInfo.AddressFamily(primary) if primary is not None else None

    def dump(self) -> dict:
        r = dict()
        r["ipv4"] = self.ipv4.exploded if self.ipv4 is not None else None
        if self.ipv4_remote is not None:
            r["ipv4_remote"] = self.ipv4_remote
        r["ipv6"] = self.ipv6.exploded if self.ipv6 is not None else None
        if self.ipv6_remote is not None:
            r["ipv6_remote"] = self.ipv6_remote
        r["primary"] = self.primary.value if self.primary is not None else None
        return r

    @property
    def is_valid(self) -> bool:
        return self.ipv4 is not None or self.ipv6 is not None

    @staticmethod
    def get_ip(timeout: float=10.0):

        result = IPInfo()
        try:
            url = "https://ifconfig.co/json"
            headers = {
                #"User-Agent": USER_AGENT,
            }
            next_req_af = None
            response, af = IPInfo.do_get(url, headers, timeout)
            if response.status == 200:
                data = json.load(response)
                next_req_af = result._parse_ip_json(data, af[0], set_primary=True)
            if next_req_af is not None:
                response, af = IPInfo.do_get(url, headers, timeout, af_family=next_req_af)
                if response.status == 200:
                    data = json.load(response)
                    result._parse_ip_json(data, af[0])
            return result if result.is_valid else None
        except Exception as e:
            print(e, file=sys.stderr)
            return result if result.is_valid else None

    def _parse_ip_json(self, data: dict, af: socket.AddressFamily, set_primary: bool = False) -> socket.AddressFamily:
            if af == socket.AF_INET:
                self.ipv4 = ip_address(data.get("ip"))
                self.ipv4_remote = data.get("hostname")
                if set_primary:
                    self.primary = IPInfo.AddressFamily.IPv4
                    return socket.AF_INET6
            elif af == socket.AF_INET6:
                self.ipv6 = ip_address(data.get("ip"))
                self.ipv6_remote = data.get("hostname")
                if set_primary:
                    self.primary = IPInfo.AddressFamily.IPv6
                    return socket.AF_INET
            return None

    @staticmethod
    def do_get(url: str, headers: dict, timeout: float = 5.0, af_family: int = 0) -> Tuple[HTTPResponse, List[socket.AddressFamily]]:

        af_family_last = list()
        def create_connection_with_af(address: Tuple[str, int], timeout: float = socket._GLOBAL_DEFAULT_TIMEOUT, source_address = None):
            host, port = address
            err = None
            for res in socket.getaddrinfo(host, port, af_family, socket.SOCK_STREAM):
                af, socktype, proto, canonname, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                        sock.settimeout(timeout)
                    if source_address:
                        sock.bind(source_address)
                    sock.connect(sa)
                    # Break explicitly a reference cycle
                    err = None
                    af_family_last.append(af)
                    return sock
                except OSError as e:
                    err = e
                    if sock is not None:
                        sock.close()
            if err is not None:
                try:
                    raise err
                finally:
                    # Break explicitly a reference cycle
                    err = None
            else:
                raise OSError("getaddrinfo returns an empty list")
            
        parts = urlparse(url)
        conn = HTTPSConnection(host=parts.hostname, port=parts.port, timeout=timeout)
        conn._create_connection = create_connection_with_af
        conn.request("GET", parts.path, headers=headers)
        response = conn.getresponse()
        return response, af_family_last


def parse_smtp_netloc(smtp_netloc: str) -> Tuple[str, int]:
    i = smtp_netloc.rfind(":")
    if i == -1:
        return smtp_netloc, 0
    return smtp_netloc[:i], int(smtp_netloc[i+1:])

def main(args: List[str]):

    # args[0]: cache file
    cache_file = args[0]
    # args[1]: SMTP host
    smtp_netloc = parse_smtp_netloc(args[1])
    # args[2]: SMTP email address
    smtp_email_sender = args[2]
    # args[3]: SMTP password
    smtp_password = args[3]
    # args[4]: SMTP email receiver
    smtp_email_reciever = args[4]
    # args[5]: timeout in milliseconds; optional
    timeout = float(args[5]) if len(args) > 5 else 10.0 * 1000.0


    new_ip = IPInfo.get_ip(timeout=timeout / 1000.0)
    if new_ip is None:
        print("Failed to get IP address", file=sys.stderr)
        exit(1)
    
    old_ip = IPInfo()
    try:
        with open(cache_file, "r") as ifile:
            data = json.load(ifile)
            old_ip = IPInfo(**data)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(e, file=sys.stderr)

    need_update = False
    if not new_ip.ipv4 == old_ip.ipv4:
        print("IPv4 address changed from %s to %s" % (old_ip.ipv4, new_ip.ipv4))
        need_update = True
    if not new_ip.ipv6 == old_ip.ipv6:
        print("IPv6 address changed from %s to %s" % (old_ip.ipv6, new_ip.ipv6))
        need_update = True
    if not new_ip.primary == old_ip.primary:
        print("Primary address changed from %s to %s" % (old_ip.primary, new_ip.primary))
        need_update = True
    
    with open(cache_file, "w") as ofile:
        data = new_ip.dump()
        json.dump(data, ofile, indent=4)

    if not need_update:
        print("No change in IP address")
        exit(0)

    try:
        smtp_client = SMTP_SSL(host=smtp_netloc[0], port=smtp_netloc[1])
        smtp_client.login(smtp_email_sender, smtp_password)
        msg = EmailMessage()
        msg['Subject'] = "Rock5b IP address changed"
        msg['From'] = smtp_email_sender
        msg['To'] = smtp_email_reciever
        msg.set_content("ipv4: %s\r\nipv6: %s\r\nprimary: %s\r\n" % (new_ip.ipv4, new_ip.ipv6, new_ip.primary.value))
        smtp_client.send_message(msg)
        smtp_client.quit()
        print("Email sent")
    except Exception as e:
        print(e, file=sys.stderr)
        exit(1)


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) == 0:
        args = input("> ").split()
    main(args)
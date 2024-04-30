# https://docs.google.com/document/d/19JJUlr_MQSPjTnZ-4nfMJso7HXRdWoYgWBEr6I_EPiY/edit#heading=h.585s1053t9xd
import struct
import socket
import select
from time import time


def checksum(source_string):
    """подсчет хэша icmp пакета"""
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xFFFFFFFF
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xFFFFFFFF
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xFFFF
    answer = answer >> 8 | (answer << 8 & 0xFF00)
    return answer


def create_packet(id):
    """icmp пакет с id = id"""
    ICMP_ECHO_REQUEST = 8
    header = struct.pack("bbHHh", 8, 0, 0, id, 1)
    data = b"hello!"
    my_checksum = checksum(header + data)
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1
    )
    return header + data


class Pong:
    pong: bool
    ip: str
    id: int
    time: int

    def __init__(self, pong, ip, id, time) -> None:
        self.pong = pong
        self.ip = ip
        self.id = id
        self.time = time


def ping(name: str, ttl: int, id: int):
    """отправляет icmp ping"""

    # создание необработанного icmp сокета
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        # устанавливаем ttl
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # icmp пакет с id = id
        data = create_packet(id)
        # время отправки
        t = time()
        try:
            # отправляем пакет
            s.sendto(data, (name, 0))
        except socket.gaierror:
            print(f"{name} is invalid")
            exit(0)

        # ждём ответ
        r = select.select([s], [], [], 1)[0]
        if not r:
            return Pong(False, name, id, -1)
        r = r[0].recvfrom(2048)

        # проверяем является ли пакет отчётом об ошибке type=11, code=0
        if r[0][20] == 11 and r[0][21] == 0:
            res = Pong(
                False,
                r[1][0],
                struct.unpack("!H", r[0][52:54])[0],
                int((time() - t) * 100000) / 100,
            )

        # проверяем является ли пакет reply type=0, code=0
        if r[0][20] == 0 and r[0][21] == 0:
            res = Pong(True, r[1][0], id, int((time() - t) * 100000) / 100)

        return res


def get_whois_server(name: str):
    """определяет whois сервер, к которому следует обратиться, чтобы узнать о name"""
    whois = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(("whois.iana.org", 43))
        s.send(name.encode() + b"\r\n")
        while True:
            r = s.recv(1024)
            if len(r) == 0:
                break
            for i in r.decode("utf-8").split():
                if "whois" in i and ":" not in i:
                    whois = i
                    break
    return whois


def get_whois_info(name: str):
    """запрос информации о name к базе whois"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        whois = get_whois_server(name)
        if not whois:
            return None
        s.connect((whois, 43))
        s.send(name.encode() + b"\r\n")
        all = b""
        while True:
            r = s.recv(1024)
            if len(r) == 0:
                break
            all += r
    return {
        j[0][:-1].lower(): j[1]
        for j in [
            i.split()
            for i in all.decode().split("\n")
            if i.split() and i.split()[0].lower() in "origin:country:netname:"
        ]
    }


def tracert(name: str, max_ttl: int = 255):
    pong = ping(name, 255, 255)
    if not pong.pong:
        print(f"{name} unreachable")
        return
    last_unreachable = False
    for ttl in range(1, max_ttl):
        pong = ping(name, ttl, ttl)
        if pong.time == -1:
            if last_unreachable:
                continue
            last_unreachable = True
            print(f"{ttl}. *\r\n\r\n", end="")
        else:
            last_unreachable = False
            whois = get_whois_info(pong.ip)
            if not whois:
                print(f"{ttl}. {pong.ip}\r\nlocal\r\n\r\n", end="")
            else:
                tmp = []
                if "netname" in whois:
                    tmp.append(whois["netname"])
                elif "origin" in whois:
                    tmp.append(whois["origin"])
                elif "country" in whois:
                    tmp.append(whois["country"])
                print(f'{ttl}. {pong.ip}\r\n{", ".join(tmp)}\r\n\r\n', end="")
        if pong.pong:
            break


def main(name: str):
    try:
        tracert(name)
    except OSError:
        print("возможно нужно больше прав")


import sys

if __name__ == "__main__":
    args = sys.argv
    if len(args) == 2:
        main(args[1])
    else:
        print("введите адрес или ip")

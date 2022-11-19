#!/usr/bin/env python
import socket
from multiprocessing import Process, Queue
import time
import argparse
import subprocess


def check_server(address, port, queue):
    s = socket.socket()
    try:
        s.connect((address, port))
        queue.put((True, address, port))
    except socket.error as error:
        queue.put((False, address, port))


def own_ip():
    ip = ((([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")] or [[(s.connect(
        ("8.8.8.8", 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) + ["no IP found"])[0])
    print(f'Got own ip: {ip}')
    return ip


def own_subnet():
    ip = own_ip()
    ip_split = ip.split('.')
    subnet = ip_split[:-1]
    return '.'.join(subnet)


def check_subnet_for_open_port(subnet, port, timeout=3.0):
    q = Queue()
    processes = []
    for i in range(1, 255):
        ip = subnet + '.' + str(i)
        p = Process(target=check_server, args=[ip, port, q])
        processes.append(p)
        p.start()
    time.sleep(timeout)

    found_ips_with_port = []
    for idx, p in enumerate(processes):
        if p.exitcode is None:
            p.terminate()
        else:
            open_ip, address, port = q.get()
            if open_ip:
                found_ips_with_port.append([address, port])

    for idx, p in enumerate(processes):
        p.join()

    return found_ips_with_port


def check_own_subnet_for_open_port(port):
    return check_subnet_for_open_port(own_subnet(), port)


def check_subnet():
    process = {}
    subnet = own_subnet()
    for ping in range(1, 255):
        ip = subnet + '.' + str(ping)
        process[ip] = subprocess.Popen(
            ['ping', '-c', '5', '-i', '3', ip], stdout=subprocess.DEVNULL)
    while process:
        for ip, proc in process.items():
            if proc.poll() is not None:
                del process[ip]
                if proc.returncode == 0:
                    print(f'{ip} active')
                break


def parse_arguments():
    default_port = 22
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--ping', action=argparse.BooleanOptionalAction, help='if only ping all address')
    parser.add_argument('-s', '--subnet', type=str,
                        help='subnet, example 192.168.0')
    parser.add_argument('-p', '--port', type=int,
                        help='port, example 22', default=default_port)

    params = parser.parse_args()

    return params


def print_address(address):
    for item in address:
        print(f'{item[0]}:{item[1]}')


def main(config):
    if config.ping:
        check_subnet()
    elif not config.subnet:
        print_address(check_own_subnet_for_open_port(config.port))
    else:
        print_address(check_subnet_for_open_port(config.subnet, config.port))


if __name__ == '__main__':
    main(parse_arguments())

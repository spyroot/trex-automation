#!/usr/bin/env python
from __future__ import print_function

"""
    Script adjust vmk port IP every time StrongSwan 
    establish a new VPN session.  // it short term fix for ESXi behind a NAT

    Mustafa Bayramov
    mbayramov@vmware.com
"""
import paramiko
import sys
import yaml
import time
import sys


def sendcommand(host_config=None, cmd=None, verbose=False):
    """

    :param host_config:
    :param cmds:
    :param verbose:
    :return:
    """
    client = None

    if verbose is True:
        print("connecting to {0} username {1} password {2}".format(host_config['host'],
                                                                   host_config['username'],
                                                                   host_config['password']))
    try:

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(host_config['host'],
                       port=host_config['port'],
                       username=host_config['username'],
                       password=host_config['password'], pkey=None)

        "esxcli system uuid get"
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=False)
        respond = stdout.read().split(' ')
        if len(respond) > 0:
            return respond[0].rstrip()

    finally:
        if client is not None:
            client.close()

    return None


if __name__ == "__main__":

    print(sys.argv[1])
    config = {'host': "192.168.10.99", 'port': "22", 'username': "root", 'password': "VMware1!"}
    sendcommand(host_config=config, cmd="esxcli network ip interface ipv4 set --ipv4={0} --netmask=255.255.255.0 --interface-name=vmk2 --type=static".format(sys.argv[1]))
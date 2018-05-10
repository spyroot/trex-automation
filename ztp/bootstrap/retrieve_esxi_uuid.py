#!/usr/bin/env python
from __future__ import print_function

"""
    Simple script that retrieve host uuid from ESXI via back-to-back loopback link.
    Default network should 192.168.10.0/24 - ESXi IP 192.168.10.99

    Mustafa Bayramov
    mbayramov@vmware.com
"""
import paramiko
import sys
import yaml
import time


def sendcommand(host_config=None, cmd=None, verbose=False):
    """

    Send ssh command to remote host.

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
    """
    """
    default_config = yaml.load(open("config/default.yaml"))
    config = {'host': default_config['vcenter']['default_ip'], 'port': "2222",
              'username': default_config['vcenter']['default_esxi_username'],
              'password': default_config['vcenter']['default_esxi_password']}
    host_uuid = sendcommand(host_config=config,  cmd="esxcli system uuid get")
    print(host_uuid)
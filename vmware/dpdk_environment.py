#!/usr/bin/env python
"""
    Setups dpdk and ens environment.

    Mustafa Bayramov
    mbayramov@vmware.com
"""
import paramiko
import sys
import yaml
import time


def openssh(host_config=None, cmds=None, verbose=False):
    """

    :param host_config:
    :param cmds:
    :param verbose:
    :return:
    """
    client = None

    if verbose is True:
        print "connecting to {0} username {1}".format(host_config['host'], host_config['username'])

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy)
        client.connect(host_config['host'],
                       port=host_config['port'],
                       username=host_config['username'],
                       password=host_config['password'])

        for cmd in cmds:
            stdin, stdout, stderr = client.exec_command(cmd, get_pty=False)
            #if stdout.channel.recv_exit_status() is not 0:
            #    print "cmd {0} failed.".format(cmd)
    finally:
        if client is not None:
            client.close()


def teardown_environment(config_name):
    """

    :param config_name:
    :return:
    """
    try:
        config = yaml.load(open(config_name))
        for host_config in config['dpkd-hosts']:
            openssh(host_config=host_config, cmds=[host_config['forward-stop']])
    except KeyError as e:
        print "Mandatory key not present. Check configuration yaml file."
    except TypeError as e:
        print "Check configuration yaml file."


def setup_environment(config_name):
    """

    :param config_name:
    :return:
    """
    config = yaml.load(open(config_name))

    try:
        for host_config in config['dpkd-hosts']:
            openssh(host_config=host_config, cmds=[host_config['forward-stop']])
            openssh(host_config=host_config, cmds=[host_config['forward-start']])

        # we sleep 2 second and give time to all l3fwd start
        time.sleep(2)
        for esxi_host in config['esxi-hosts']:
            cmd_list = []
            for cli in esxi_host['nsxdp-cli']:
                cmd_list.append(cli['cmd'])
            if len(cmd_list) > 0:
                openssh(host_config=esxi_host, cmds=cmd_list)
    except KeyError as e:
        print "Mandatory key not present. Check configuration yaml file."
    except TypeError as e:
        print "Check configuration yaml file."


if __name__ == "__main__":
    setup_environment("")
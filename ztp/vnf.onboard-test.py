#!/usr/bin/python
"""

 Test script can trigger second phase VNF on-boarding without
 actually doing any VPN.

 You just need to make sure vCenter has reachability to remote ESXi
 host

Mustafa Bayramov
mbayramov@vmware.com
"""

import logging
import pika
import yaml
import argparse


def main(esx_hostname):
    """

    :param esx_hostname:
    :return:
    """
    default_config = yaml.load(open("config/default.yaml"))

    credentials = pika.PlainCredentials(default_config['ampq']['username'], default_config['ampq']['password'])
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=default_config['ampq']['hostname'],
                                  credentials=credentials))

    channel = connection.channel()
    channel.queue_declare(queue='vnfonboarding')
    channel.basic_publish(exchange='',
                          routing_key='vnfonboarding',
                          body=esx_hostname)
    connection.close()
    logging.info("Pushed job to a queue")


if __name__ == "__main__":
    """

    Main entry for VNF on boarding listner.

    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-hh', '--hostname', help='Hostname of esxi', required=True)
    args = vars(parser.parse_args())

    if args['hostname']:
        main(args['hostname'])


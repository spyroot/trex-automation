#!/usr/bin/python
"""

 This script used as by strong swan to queue a new host to rabbit queue.
 It used as trigger to detect a new host

Mustafa Bayramov
mbayramov@vmware.com
"""

import inspect
import time
import subprocess
import sys
import os
import logging
import time
import pika
import socket


logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s',
    filename='/home/vmware/scripts/default.log',
    level=logging.INFO)

if __name__ == "__main__":

    if "PLUTO_VERB" not in os.environ:
        exit()

    if os.environ['PLUTO_VERB'] != "up-client":
        exit()

    if "PLUTO_PEER_CLIENT" not in os.environ:
        logging.warning('PLUTO_PEER_CLIENT environ is missing. '
                        'In order add a host to vCenter, caller must indicate PLUTO_PEER_CLIENT environ')
        exit()

    host_ip = os.environ['PLUTO_PEER_CLIENT'].split("/")[0]  # pluto peer client in format ip/32
    host_ip = host_ip.strip()
    hostname = socket.gethostbyaddr(host_ip)[0]

    logging.info("forking on board script for {0}".format(host_ip))
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()
    channel.queue_declare(queue='onboarding')
    channel.basic_publish(exchange='', routing_key='onboarding', body=hostname)
    connection.close()
    logging.info("Pushed job to a queue")

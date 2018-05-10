#!/usr/bin/python
"""

  Upon a boot, an ESXi builds IPSec tunnel to VPN headend that triggers on boarding sequence.
  The VPN headend assigned dynamic IP address from the pool, and network must is reachable must from the vCenter.
  VPN headed can that pool via BGP to upstream network in order create that reachability.


   Because we want support a case where and remote host uses dynamic IP address
   we use a FQDN name as ESXi endpoint in vCenter.

   Upon successful tunnel establishment bootstrap initial bootstrap push a data to AMPQ.
   This script de-queue event and starts ESXi on-boarding sequence.

   If the hostname already on-boarded and state is disconnected it will try to re-connect
   if reconnect fail script will remove a host from vCenter and re-adds it back.

Mustafa Bayramov
mbayramov@vmware.com
"""

import atexit
import yaml
import inspect
import time
import subprocess
import ssl
import sys
import os
from pyVim import connect
import logging
import dataset
import time
import pika

from pyVim.connect import SmartConnect
from pyVmomi import vim
import ssl

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[ logging.FileHandler("esxi_onboarding.log"), logging.StreamHandler(sys.stdout)],
    level=logging.INFO)

# we remove cert verification for dev purpose
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_NONE

# read configuration from default.yaml
config = yaml.load(open("config/default.yaml"))

si = SmartConnect(host=config["vcenter"]["ip"],
                  user=config["vcenter"]["user"],
                  pwd=config["vcenter"]["password"], port=443,
                  sslContext=context)

content = si.content


class Vcenter(object):
    """

    """
    def __init__(self, vcenter_params):
        """

        :param vcenter_params:
        """
        self.pyVmomi = __import__("pyVmomi")
        self.server = vcenter_params['ip']
        self.username = vcenter_params['user']
        self.password = vcenter_params['password']
        self.connect()

    def create_datacenter(self, dcname=None, folder=None):
        """

        :param dcname:
        :param folder:
        :return:
        """
        datacenter = self.get_obj([self.pyVmomi.vim.Datacenter], dcname)
        if datacenter is not None:
            logging.debug("Datacenter {0} already exists.".format(dcname))
            return datacenter
        else:
            if len(dcname) > 79:
                raise ValueError("The name of the datacenter must be under 80 characters.")
            if folder is None:
                folder = self.service_instance.content.rootFolder
            if folder is not None and isinstance(folder, self.pyVmomi.vim.Folder):
                print("Creating Datacenter %s " % dcname)

                dc_moref = folder.CreateDatacenter(name=dcname)
                return dc_moref

    def create_cluster(self, cluster_name, datacenter):

        """

        :param cluster_name:
        :param datacenter:
        :return:
        """
        cluster = self.get_obj([self.pyVmomi.vim.ClusterComputeResource], cluster_name)
        if cluster is not None:
            logging.info("Cluster {0} already exists.".format(cluster_name))
            return cluster
        else:
            if cluster_name is None:
                raise ValueError("Missing value for name.")
            if datacenter is None:
                raise ValueError("Missing value for datacenter.")

            logging.info("Creating Cluster {0}".format(cluster_name))
            cluster_spec = self.pyVmomi.vim.cluster.ConfigSpecEx()
            host_folder = datacenter.hostFolder
            cluster = host_folder.CreateClusterEx(name=cluster_name, spec=cluster_spec)
            return cluster

    def add_host(self, cluster_name, hostname, sslthumbprint, username, password):
        """

        :param cluster_name:
        :param hostname:
        :param sslthumbprint:
        :param username:
        :param password:
        :return:
        """
        host = self.get_obj([self.pyVmomi.vim.HostSystem], hostname)
        if host is not None:
            print("host already exists")
            return host
        else:
            if hostname is None:
                raise ValueError("Missing value for name.")
            cluster = self.get_obj([self.pyVmomi.vim.ClusterComputeResource], cluster_name)
            if cluster is None:
                error = 'Error - Cluster %s not found. Unable to add host %s' % (cluster_name, hostname)
                raise ValueError(error)

            try:
                hostspec = self.pyVmomi.vim.host.ConnectSpec(hostName=hostname, userName=username,
                                                             sslThumbprint=sslthumbprint, password=password, force=True)
                task = cluster.AddHost(spec=hostspec, asConnected=True)
            except self.pyVmomi.vmodl.MethodFault as error:
                print "Caught vmodl fault : " + error.msg
                return -1
            self.wait_for_task(task)
            host = self.get_obj([self.pyVmomi.vim.HostSystem], hostname)
            return host

    def get_obj(self, vimtype, name):
        """
        Get the vsphere object associated with a given text name
        """
        obj = None
        container = self.content.viewManager.CreateContainerView(self.content.rootFolder, vimtype, True)
        for c in container.view:
            if c.name == name:
                obj = c
                break
        return obj

    def wait_for_task(self, task):

        """

        :param task:
        :return:
        """
        while task.info.state == (self.pyVmomi.vim.TaskInfo.State.running or self.pyVmomi.vim.TaskInfo.State.queued):
            time.sleep(2)

        if task.info.state == self.pyVmomi.vim.TaskInfo.State.success:
            if task.info.result is not None:
                out = 'Task completed successfully, result: %s' % (task.info.result,)
                print out
        elif task.info.state == self.pyVmomi.vim.TaskInfo.State.error:
            out = 'Error - Task did not complete successfully: %s' % (task.info.error,)
            raise ValueError(out)
        return task.info.result

    def connect(self):
        """

        """
        logging.info("Connecting to {0} using username {1}".format(self.server, self.username))
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.verify_mode = ssl.CERT_NONE
        self.service_instance = connect.SmartConnect(host=self.server,
                                                     user=self.username,
                                                     pwd=self.password,
                                                     port=443, sslContext=context)
        self.content = self.service_instance.RetrieveContent()
        about = self.service_instance.content.about
        logging.info("Connected to {0}, {1}".format(self.server, about.fullName))
        atexit.register(connect.Disconnect, self.service_instance)

    def getsslThumbprint(self, ip):
        """

        Gets ssl thumbprint from remote host.

        :param ip:
        :return:
        """
        hostport=ip+":443"
        p1 = subprocess.Popen(('/bin/echo', '-n'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p2 = subprocess.Popen(('/usr/bin/openssl', 's_client', '-connect',  hostport),stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p3 = subprocess.Popen(('/usr/bin/openssl', 'x509', '-noout', '-fingerprint', '-sha1'), stdin=p2.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = p3.stdout.read()
        ssl_thumbprint = out.split('=')[-1].strip()
        #if ssl_thumbprint and ssl_thumbprint.strip():
        #    return None
        logging.info("SSL thumprint for a host {} : {}".format(ip, ssl_thumbprint))
        return ssl_thumbprint


def get_esxi_host(target_host=None):
    """

    Search and return vim.HostSystem

    :param target_host:
    :return: vim.HostSystem
    """

    objview = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True)
    esxi_hosts = objview.view

    # we search for target ESXi system in vCenter inventory
    for esxi_host in esxi_hosts:
        if target_host == esxi_host.name:
            return esxi_host

    return None


def reconnect_esxi_host(hostname=None):
    """

     Reconnect a host to vCenter


    :param hostname:
    :return:
    """

    esxi_host = get_esxi_host(hostname)
    reconnect_retry = 0
    if esxi_host is None:
        return False

    if esxi_host.runtime.connectionState == 'connected':
        logging.info("Host already connect to vCenter {0}".format(esxi_host.name))
        return True

    if esxi_host.runtime.connectionState == 'disconnected':
        logging.info("Reconnecting host to vCenter {0}".format(esxi_host.name))

    while not esxi_host.runtime.connectionState == 'connected':
        if reconnect_retry == 3:
            return False

        esxi_host.Reconnect()
        time.sleep(1)
        reconnect_retry += 1

    if esxi_host.runtime.connectionState.connected:
        return True
    else:
        logging.info("Failed reconnect a host to vCenter {0}".format(esxi_host.name))
        return False


def remove_esxi_host(hostname=None):
    """

    Function remove host from vCenter

    :param hostname:
    :return:
    """
    esxi_host = get_esxi_host(hostname)
    if esxi_host is None:
        return False

    logging.info("Disconnecting host from inventory {0}".format(esxi_host.name))
    esxi_host.Disconnect()
    #    host.EnterMaintenanceMode(timeout=0, evacuatePoweredOffVms=True, maintenanceSpec=None)
    while not esxi_host.runtime.connectionState == 'disconnected':
        time.sleep(1)

    logging.info("Removing host from inventory {0}".format(esxi_host.name))

    task_destroyhost = esxi_host.Destroy()
    while task_destroyhost.info.state == vim.TaskInfo.State.running:
        time.sleep(1)

    if task_destroyhost.info.state != vim.TaskInfo.State.success:
        logging.info("Failed remove host from vCenter".format(esxi_host.name))

    logging.info("Host removed from vCenter".format(esxi_host.name))


def child(host_ip):
    """

      Main ESXi on boarding logic.

    :return:
    """
    #os.environ['PLUTO_PEER_CLIENT'] = str("10.10.10.3/32")
    #os.environ['PLUTO_VERB'] = str("up-client")
    #time.sleep(2)

    logging.info("Reading default.yaml")

    db = dataset.connect('sqlite:///endpoints.db')
    table = db['endpoints']

    vc = Vcenter(config["vcenter"])
    dcs = config["vcenter"]["topology"]

    logging.info("Starting on-boarding sequence for {0}".format(host_ip))
    result = table.find_one(endpoint=host_ip)
    if result is not None:
        logging.info("Host already in database. Verifying thumbprint cert.")
        ssl_thumbprint = vc.getsslThumbprint(host_ip)  # get ssl thumbprint from esxi
        if ssl_thumbprint == result['thumbprint']:
            logging.info("Host already on-boarded.")
            if not reconnect_esxi_host(hostname=host_ip):
                remove_esxi_host(hostname=host_ip)
                table.delete(endpoint=host_ip)
            else:
                logging.info("Host already connected to vCenter.")
                # it already in db and connected so we do nothing.
                return None
        else:
            logging.info("Host in the database but thumbprint is different. possible IP duplicate.")
            if not reconnect_esxi_host(hostname=host_ip):
                remove_esxi_host(hostname=host_ip)
                table.delete(endpoint=host_ip)
            return None

    logging.info("Starting on boarding sequence for host {0}".format(host_ip))
    ssl_thumbprint = vc.getsslThumbprint(host_ip)  # get ssl thumbprint from esxi
    if ssl_thumbprint is None:
        # it edge case we can't really do much
        logging.warning("Host certificate is empty.")
        return None

    logging.info("Host ssl thumbprint {0}".format(ssl_thumbprint))
    host = vc.get_obj([vc.pyVmomi.vim.HostSystem], host_ip)
    if host is not None:
        logging.warning("Host already exists.")
        # we reconnect if need if we fail we remove host otherwise do nothing
        if not reconnect_esxi_host(hostname=host_ip):
            remove_esxi_host(hostname=host_ip)
            table.delete(endpoint=host_ip)
        else:
            # we reconnected host nothing to do more
            return host

    for dc in dcs:
        if dc.has_key('name') and dc.has_key('clusters'):
            clusters = dc['clusters']
            dcname=dc['name']
            logging.info("Verifying data center name {0}".format(dcname))
            for cluster in clusters:
                cluster_name = cluster['name']
                logging.info("Verifying cluster name {0}".format(cluster['name']))
                res = vc.create_cluster(cluster['name'], dcname)
                if res is None:
                    logging.info("Failed create cluster.")
                    return None

                if ssl_thumbprint is None:
                    logging.info("esxi host ssl thumbprint is empty.")
                    return None

                logging.info("Adding a new host {0} to vCenter {1}".format(host_ip, ssl_thumbprint))
                esx_username = config["vcenter"]["default_esxi_username"]
                esx_password = config["vcenter"]["default_esxi_password"]
                logging.info("cluster name {0}, username {1} password {2}".format(cluster_name, esx_username, esx_password))
                vc.add_host(cluster_name, host_ip, ssl_thumbprint, esx_username, esx_password)
                table.insert(dict(endpoint=host_ip, thumbprint=ssl_thumbprint))
                return 0

    return 0


def get_all_objs(content, vimtype):
    """

    Returns object from vCenter.

    :param content:
    :param vimtype:
    :return:
    """
    obj = {}
    container = content.viewManager.CreateContainerView(
        content.rootFolder, vimtype, True)
    for managed_object_ref in container.view:
        obj.update({managed_object_ref: managed_object_ref.name})
    return obj


def callback(ch, method, properties, body):
    """

    Main callback called to on board a host

    :param ch:
    :param method:
    :param properties:
    :param body:
    :return:
    """
    child(body)
    hostname = body
    allhosts = get_all_objs(content, [vim.HostSystem])
    for h in allhosts:
        if hostname in h.name:
            logging.info("ESXi host added to vCenter.")

            # we create new task to on board VNF's now.
            logging.getLogger("pika").setLevel(logging.WARNING)
            credentials = pika.PlainCredentials('admin', 'password')
            connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.254.244',
                                                                           credentials=credentials))
            channel = connection.channel()
            channel.queue_declare(queue='vnfonboarding')
            channel.basic_publish(exchange='', routing_key='vnfonboarding', body=hostname)
            connection.close()
            logging.info("Staging VNF on-boarding.")


if __name__ == "__main__":
    """
    """
    logging.getLogger("pika").setLevel(logging.WARNING)
    credentials = pika.PlainCredentials('admin', 'password')
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='192.168.254.244',
                                                                   credentials=credentials))
    channel = connection.channel()
    channel.queue_declare(queue='onboarding')
    channel.basic_consume(callback, queue='onboarding', no_ack=True)

    logging.info('  Waiting for on boarding messages. To stop press CTRL+C')
    try:
        channel.start_consuming()
    except KeyboardInterrupt:
        channel.stop_consuming()
    connection.close()
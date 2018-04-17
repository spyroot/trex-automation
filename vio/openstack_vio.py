#!/usr/bin/env python -u
"""

 Example basic VIO interaction.

 - Inject ssh pub key
 - Download QCOW image from internet
 - Convert image to VMDK
 - Patch it if it corrupted
 - Upload image to a glance
 - Create new instance in default availability zone
 - Attach nic to external network

 - Gets a list flavor from VIO
 - Gets a list availability zones
 - Gets a list of network from VIO
 - Gets list of images from VIO

Mustafa Bayramov mbayramov@vmware.com

"""
from __future__ import print_function

import datetime
import os.path
import socket
import sys
import time
import pprint
import ssl
import pbr.version
import urllib2
import progressbar

from pathlib import Path
from subprocess import call
from prettytable import PrettyTable

from novaclient import client as novaclient
from neutronclient.v2_0 import client as neutronclient
from glanceclient import Client as glanceclient
from keystoneauth1 import identity
from keystoneauth1 import loading
from keystoneauth1 import session
import urllib3

urllib3.disable_warnings()

# Openstack globals
AUTH_URL = "https://vio.corp.local:5000/v3"
USERNAME = "mustafa"
PASSWORD = "Mustafa123!"
TENANT_NAME = "ntt"
VERSION = 2.0
PROJECT_DOMAIN_ID = 'default'
USER_DOMAIN_ID = 'default'

# Image globals
GLANCE_IMAGE_NAME = "TestImage7"
IMAGE_URL = "http://download.cirros-cloud.net/0.4.0/cirros-0.4.0-x86_64-disk.img"
IMAGE_NAME = "cirros-0.4.0-x86_64-disk.img"
IMAGE_DIR = "/tmp"
PATH_TO_QCOW = IMAGE_DIR + '/' + IMAGE_NAME

# Project settings
DEFAULT_KEYNAME = "mykey"
DEFAULT_AVAILABILITY_ZONE = "MDC1"
DEFAULT_FLAVOR = "m1.tiny"
DEFAULT_EXTERNAL = "external"

if os.environ.get('http_proxy') or os.environ.get('https_proxy'):
    print("proxy set")

_create_unverified_https_context = ssl._create_unverified_context
ssl._create_default_https_context = _create_unverified_https_context


def download_image(url=None):
    """

    :return:
    """

    file_name = url.split('/')[-1]
    if len(file_name) is 0:
        return False

    try:
        u = urllib2.urlopen(url)
        path_to_file = IMAGE_DIR + '/' + file_name
        print(path_to_file)

        with open(path_to_file, 'wb') as f:
            meta = u.info()
            file_size = int(meta.getheaders("Content-Length")[0])
            print("Downloading: %s Bytes: %s" % (file_name, file_size))

            file_size_dl = 0
            block_sz = 8192
            num_bars = file_size / block_sz

            download_bar = progressbar.ProgressBar(maxval=num_bars).start()
            progress_counter = 0

            while True:
                r_buffer = u.read(block_sz)
                if not r_buffer:
                    break
                file_size_dl += len(r_buffer)
                f.write(r_buffer)
                download_bar.update(progress_counter)
            progress_counter += 1
            f.close()

    except IOError as e:
        print(e.message)

    return True


def convert_image(qcow_image=None):
    """

    :return:
    """
    # A convert QCOW to VMDK
    new_filename = Path(qcow_image).stem + ".vmdk"
    path_to_vmdk = str(Path(qcow_image).parent.joinpath(new_filename))

    if os.path.isfile(path_to_vmdk) is False:
        print("Creating vmdk image.")
        # convert qcow2 to vmdk
        call(["/usr/local/bin/qemu-img",
              "convert", "-f", "qcow2", "-O", "vmdk",
              "-o", "subformat=streamOptimized",
              "-o", "adapter_type=lsilogic", PATH_TO_QCOW, path_to_vmdk])

        # fix qemu-img bug and write hdr
        payload = b'\xe2\x80\x98\x78\x30\x33\xe2\x80\x99'
        with open(path_to_vmdk, "r+b") as f:
            f.seek(4)
            f.write(payload)
        f.close()

    return path_to_vmdk


def push_sshkey(nova_endpoint=None):
    """

    :param nova_endpoint:
    :return:
    """
    if not nova_endpoint.keypairs.findall(name=DEFAULT_KEYNAME):
        print("Creating keypair: mykey...")
        with open(os.path.expanduser('~/.ssh/id_rsa.pub')) as fpubkey:
            print("Uploading keypair: mykey...")
            nova.keypairs.create(name=DEFAULT_KEYNAME, public_key=fpubkey.read())
    print("SSH key already in the project.")


def get_availability_zones_tbl(nova_endpoint=None):
    """

    :return:
    """
    availability_zones = PrettyTable()
    availability_zones.field_names = ["Zone Name", "Zone State", "Host", "Host Role", "Type", "available", "active"]

    for zone in nova_endpoint.availability_zones.list(detailed=True):
        for hosts in zone.hosts:
            for key in zone.hosts[hosts]:
                availability_zones.add_row([zone.zoneName,
                                            zone.zoneState['available'],
                                            hosts,
                                            key,
                                            zone.hosts[hosts][key]['available'],
                                            zone.hosts[hosts][key]['active'],
                                            zone.hosts[hosts][key]['updated_at']
                                            ])
    return availability_zones


def get_flavor_table(nova_endpoint=None):
    """

    :param nova_endpoint:
    :return:
    """
    flavor_table = PrettyTable()
    flavor_table.field_names = ["ID", "Name", "Memory", "Swap", "vCPU"]

    for flavor in nova_endpoint.flavors.list(is_public=True):
        flavor_table.add_row([flavor.id, flavor.name, flavor.ram, flavor.swap, flavor.vcpus])

    return flavor_table


def get_image_table(nova_endpoint=None):
    """

    :param nova_endpoint:
    :return:
    """

    image_list = PrettyTable()
    image_list.field_names = ["ID", "Name", "Format", "Size", "Min Ram", "Mind Disk", "location",
                              "adpter type", "status", "checksum"]

    glance_list = nova_endpoint.glance.list()
    for image in glance_list:
        # location is vmware specific here
        # if you want figure out in out vcenter image deployed
        # location provide you a list
        # vi://vcenter.corp.local/Core-DC/vm/OpenStack/Project
        # (184645fce6c74642856a1a025533e700)/Images/70e98bbc-e387-443c-82da-ea6d03d37063?managed=True
        # so here we can figure out vCenter endpoint

        # here we just truncated location to 32 char for output
        if len(image.locations) > 0 and 'url' in image.locations[0]:
            loc = image.locations[0]['url'].split(" ")[0].strip()
            loc = loc[:32]
        else:
            loc = ""

        # TODO FIX this
        adapter = ""
        image_list.add_row([image.id,
                            image.name,
                            image.container_format,
                            image.size,
                            image.min_ram,
                            image.min_disk,
                            loc,
                            adapter,
                            image.status,
                            image.checksum])

    return image_list


def get_neutron_network_table(sess=None):
    """

    :param sess:
    :return:
    """
    neutron = neutronclient.Client(session=sess, insecure=True)

    n = neutron.list_networks()

    neutron_table = PrettyTable()
    neutron_table.field_names = ["ID", "Name", "subnet", "status", "admin state", "shared"]

    network_list = n['networks']
    for n in network_list:
        neutron_table.add_row([n['id'],
                               n['name'],
                               n['subnets'],
                               n['status'],
                               n['admin_state_up'],
                               n['shared']
                               ])

    return neutron_table


def push_newimage(sess):
    """
    Push new image to a glance
    :param sess:
    :return:
    """

    glance = glanceclient(version="2", session=sess)
    if os.path.isfile(PATH_TO_QCOW) is False:
        print("Downloading image...")
        download_image(IMAGE_URL)
        print("Converting image to vmdk...")
        vmdk_image = convert_image(PATH_TO_QCOW)
    else:
        new_filename = Path(PATH_TO_QCOW).stem + ".vmdk"
        vmdk_image = str(Path(PATH_TO_QCOW).parent.joinpath(new_filename))

    image_found = False
    for image in glance.images.list():
        if GLANCE_IMAGE_NAME in image.name:
            image_found = True
            break

    if not image_found:
        print("Uploading image to a glance...")
        # Crete glance image
        image = glance.images.create(name=GLANCE_IMAGE_NAME, disk_format="vmdk", container_format="bare")
        # VMware vSAN requires all images to be in streamOptimized format
        glance.images.update(image.id, vmware_adaptertype='lsiLogic')
        glance.images.update(image.id, vmware_disktype='streamOptimized')
        # Push VMDK image to glance
        glance.images.upload(image.id, open(str(vmdk_image), 'rb'))

        for image in glance.images.list():
            if GLANCE_IMAGE_NAME in image.name:
                return image.name
    else:
        print("Image already in the glance...")
        return GLANCE_IMAGE_NAME


def get_external_network(sess=None, network_name=DEFAULT_EXTERNAL):
    """

    :param network_name:
    :param sess:
    :return:
    """
    neutron = neutronclient.Client(session=sess, insecure=True)
    n = neutron.list_networks()
    network_list = n['networks']
    for n in network_list:
        if network_name in n['name']:
            return n

    return None


def create_new_instance(nova_endpoint=None,
                        instance_name=None,
                        image_name=GLANCE_IMAGE_NAME,
                        flavor_name=DEFAULT_FLAVOR,
                        key_name=DEFAULT_KEYNAME,
                        availability_zone=DEFAULT_AVAILABILITY_ZONE,
                        network_id_list=None):
    """

    :param network_id_list:
    :param availability_zone:
    :param instance_name:
    :param image_name:
    :param flavor_name:
    :param key_name:
    :param nova_endpoint:
    :return:
    """

    nics = []
    for net_id in network_id_list:
        net = {'net-id': net_id}
        nics.append(net)

    # nics = [{'net-id': '436f9c4e-5b09-4d1e-9500-1b4eb4a4ad4a'},
    #         {'net-id': '436f9c4e-5b09-4d1e-9500-1b4eb4a4ad4a'}]

    image = nova_endpoint.glance.find_image(image_name)
    if 'active' in image.status:
        flavor = nova.flavors.find(name=flavor_name)
        if flavor is not None:
            instance = nova.servers.create(name=instance_name,
                                           image=image,
                                           flavor=flavor,
                                           key_name=key_name,
                                           availability_zone=availability_zone,
                                           nics=nics)
            return instance


if __name__ == "__main__":
    """
    """

    loader = loading.get_plugin_loader('password')

    auth = identity.Password(auth_url=AUTH_URL,
                             username=USERNAME,
                             password=PASSWORD,
                             project_name="ntt",
                             project_domain_id=PROJECT_DOMAIN_ID,
                             user_domain_id=USER_DOMAIN_ID)

    nova = novaclient.Client(version=VERSION,
                             auth_url=AUTH_URL,
                             username=USERNAME,
                             password=PASSWORD,
                             project_id="85c7ca9b6cfe47c0bfa93c9a444ffe67",
                             project_name="ntt",
                             project_domain_id="Default",
                             user_domain_id="default",
                             insecure=True)

    # List availability_zones / flavor / image / networks
    print(get_flavor_table(nova_endpoint=nova))
    print(get_image_table(nova_endpoint=nova))
    print(get_image_table(nova_endpoint=nova))
    print(get_availability_zones_tbl(nova_endpoint=nova))
    sess = session.Session(auth=auth, verify=False)
    print(get_neutron_network_table(sess=sess))
    #
    ext_network = get_external_network(sess=sess)
    print("External network name '{0}' id {1}".format(ext_network['name'], ext_network['id']))

    # Push image / ssh public key
    push_sshkey(nova_endpoint=nova)
    push_newimage(sess)

    instance = create_new_instance(nova_endpoint=nova,
                                   instance_name="test_instance",
                                   network_id_list=[ext_network['id'], ext_network['id']])

    print("New instance id {0}".format(instance.id))

    sys.exit(1)

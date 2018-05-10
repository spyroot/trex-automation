#!/usr/bin/python
"""

  After ESXi on-boarding finish it push a new job to a AMPQ.
  This listener should receive event via AMPQ and start VNF on-boarding.

  In this specific case VNF listener on-boards a Velo Cloud VNF.

  In order to do that it must have access to VNF Image, the image itself my
  contain respected OVF and VMDK file.

  Script doesn't untar OVA file,  Clinet must sure it untar respected OVA file
  and upload to directory indicated in image-dir

  Example configuration in default.yaml.

  - Script must contain valid enterpriseId that is configured in Velo Cloud Orchestrator platform.
  - It must have access so Velo Cloud becase listner create Velo Edge device for each remote esxi host.
  - Prepare Profile.  In this case it called test.
  - untar velo gateway OVA file to a target dir image-dir.
    It should contain VeloCloud-Edge.ovf and respected VMDK file.

   vnf-dir:               "/Users/spyroot/PycharmProjects/ydk-netconf/vcenter/image"
   image-dir:             "/Users/spyroot/PycharmProjects/ydk-netconf/vcenter/final_image"

   enterpriseId:          42                                       # we need to know id in order to get activation key
   vce-vco:               "velo cloud host address"
   vco-username:          "mbayramov@vmware.com"
   vco-password:          "123456"
   ovf-filename:          "VeloCloud-Edge.ovf"                      # we should have ovf file and vmdk file in vnf-dir
   vnf-default-password:  "123456"                                  # default password for edge
   vnf-default-name:      "velo-edge-vc"                            # default name search on each new host
   profile-name:           "test  "                                 # VCO should have this profile
   vnf-dir:               "/Users/spyroot/PycharmProjects/ydk-netconf/vcenter/image"
   image-dir:             "/Users/spyroot/PycharmProjects/ydk-netconf/vcenter/final_image"

   In second section we need provide information about default network that listner will configure in remote ESXi
   host in order connect Velo Edge.

   You probably need change only pnic name.   pnic0/pnic1 etc. ( it must be two unused pnic on a remote host)
   for example if pnic0 used for vSwitch0

   We can assign pnic1 and pnic2 to vSwitch2 and vSwitch3.  One switch used to communicate to outside network
   (Internet / MPLS cloud and another switch used to communicate back to office network)

vnf-network:
    topology:
     - network:                1
       vswitch:                "vSwitch2"
       port-group-name:        "VeloOutside"
       pnic:                   "vusb0"                              # todo add multi pnic support
       interface-name:         ["GE1", "GE3"]
       vlan_id:                0

     - network:                 2
       vswitch:                "vSwitch3"
       port-group-name:        "VeloInside"
       pnic:                   "vusb1"
       interface-name:         ["GE2", "GE4", "GE5"]
       vlan_id:                0

Mustafa Bayramov
mbayramov@vmware.com
"""

import atexit
import re

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
import json
from time import sleep
import socket
import atexit

from pyVim import connect
from vcenter.tools import cli
from vcenter.tools import tasks
import os
import tarfile

from pyVim.connect import SmartConnect
from pyVmomi import vim
import pyVmomi

import ssl
import tarfile
from threading import Thread

import subprocess
from xml.dom.minidom import parse, parseString

from pprint import pprint
import pprint

import urllib2

import ztp.velocloud
from ztp.velocloud.rest import ApiException

import argparse


logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler("vnf_onboarding.log"), logging.StreamHandler(sys.stdout)],
    level=logging.INFO)

context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.verify_mode = ssl.CERT_NONE

parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', help='Path to config file', required=False)
args = vars(parser.parse_args())

DEFAULT_CONFIG = "config/default.yaml"
if args['config']:
    DEFAULT_CONFIG = args['config']

# read config and create default connector to vCenter.
config = yaml.load(open(DEFAULT_CONFIG))

si = SmartConnect(host=config["vcenter"]["ip"],
                  user=config["vcenter"]["user"],
                  pwd=config["vcenter"]["password"], port=443,
                  sslContext=context)

content = si.content


def get_all_objs(content, vimtype):
    """

    Return all object for a given VIM Type

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


def get_obj(content, vimtype, name):
    """

     Get the vsphere object associated with a given text name

    :param content:  Si.Content
    :param vimtype:
    :param name:
    :return:
    """

    obj = None
    container = content.viewManager.CreateContainerView(content.rootFolder,
                                                        vimtype, True)
    for view in container.view:
        if view.name == name:
            obj = view
            break
    return obj


def provision(vm):
    """

    Provisions VNF and change VNF to power on

    :param vm:
    :return:
    """

    logging.info("The current powerState is: {0}".format(vm.runtime.powerState))
    if 'poweredOn' in vm.runtime.powerState:
        logging.info("VNF already in power on state.")
    else:
        task = vm.PowerOnVM_Task()
        tasks.wait_for_tasks(si, [task])
        logging.info("The current powerState is: {0}".format(vm.runtime.powerState))


def tardir(path, tar_name):
    """

    Tars given path to a file with given name

    :param path:
    :param tar_name:
    :return:
    """
    with tarfile.open(tar_name, "w:") as tar_handle:
        for root, dirs, files in os.walk(path):
            for file in files:
                tar_handle.add(os.path.join(root, file))


def populate_ova(vnf_property_dict=None):
    """

        Populate OVF entries for a velo cloud and pack everything as single OVA image
        :type vnf_property_dict:

    """

    logging.info("OVF adaptation.")

    path_to_files = vnf_property_dict['vnf_dir'] + '/' + vnf_property_dict['ovf_filename']
    if os.path.exists(path_to_files):
        with open(path_to_files) as datasource:
            ovf_descriptor = parse(datasource)
            tag = ovf_descriptor.getElementsByTagName("ProductSection")
            for t in tag:
                for ovf_property in t.getElementsByTagName('Property'):
                    if 'velocloud.vce.vco' == ovf_property.attributes['ovf:key'].value:
                        ovf_property.attributes['ovf:value'].value = vnf_property_dict['vce.vco']

                    if 'velocloud.vce.activation_code' in ovf_property.attributes['ovf:key'].value:
                        ovf_property.attributes['ovf:value'].value = vnf_property_dict['activation_code']

                    if 'velocloud.vce.vco_ignore_cert_errors' in ovf_property.attributes['ovf:key'].value:
                        ovf_property.attributes['ovf:value'].value = "true"

                    if 'password' in ovf_property.attributes['ovf:key'].value:
                        ovf_property.attributes['ovf:value'].value = vnf_property_dict['password']

            # populate a new file
            final_dir = vnf_property_dict['image_dir'] + '/' + vnf_property_dict['target_host'] + '/'
            if not os.path.exists(final_dir):
                os.makedirs(final_dir)

            new_ovf_file = "{0}/{1}/{2}".format(vnf_property_dict['image_dir'],
                                                vnf_property_dict['target_host'],
                                                vnf_property_dict['ovf_filename'])

            with open(new_ovf_file, "wb") as file_handle:
                ovf_descriptor.writexml(file_handle, encoding="utf-8")
                file_handle.close()

    if final_dir is None:
        return None

    new_vnf_image = final_dir + '/edge.ova'
    tardir(vnf_property_dict['vnf_dir'], new_vnf_image)

    return new_vnf_image


def get_obj_in_list(obj_name, obj_list):
    """
    Gets an object out of a list (obj_list) whos name matches obj_name from vCenter inventory
    """
    for o in obj_list:
        if o.name == obj_name:
            return o
    print("Unable to find object by the name of %s in list:\n%s" % (o.name, map(lambda o: o.name, obj_list)))


def get_objects(si=None, vim_dict=None):
    """
    Returns a dict containing the necessary objects for deployment OVF container file.

    """
    # get data center object.
    datacenter_list = si.content.rootFolder.childEntity
    if 'datacenter_name' not in vim_dict:
        return False
    datacenter_obj = get_obj_in_list(vim_dict['datacenter_name'], datacenter_list)

    # get datastore object.
    datastore_list = datacenter_obj.datastoreFolder.childEntity
    if "datastore_name" in vim_dict:
        datastore_obj = get_obj_in_list(vim_dict['datastore_name'], datastore_list)
    elif len(datastore_list) > 0:
        datastore_obj = datastore_list[0]
    else:
        print("No datastores found in DC (%s)." % datacenter_obj.name)
        return False

    # Get cluster object.
    cluster_list = datacenter_obj.hostFolder.childEntity
    if 'cluster_name' in vim_dict:
        cluster_obj = get_obj_in_list(vim_dict['cluster_name'], cluster_list)
    elif len(cluster_list) > 0:
        cluster_obj = cluster_list[0]
    else:
        print("No clusters found in DC (%s)." % datacenter_obj.name)

    # Generate resource pool.
    resource_pool_obj = cluster_obj.resourcePool

    return {"datacenter": datacenter_obj,
            "datastore": datastore_obj,
            "resource pool": resource_pool_obj}


def get_ovf_descriptor(ovf_path):
    """
    Read in the OVF descriptor.
    """
    with open(ovf_path, 'r') as f:
        try:
            ovfd = f.read()
            f.close()
            return ovfd
        except:
            logging.info("Could not read file: %s" % ovf_path)


def keep_lease_alive(lease):
    """
    Keeps the lease alive while POSTing the VMDK.
    """
    while True:
        sleep(5)
        try:
            # Choosing arbitrary percentage to keep the lease alive.
            lease.HttpNfcLeaseProgress(50)
            if lease.state == vim.HttpNfcLease.State.done:
                return
            # If the lease is released, we get an exception.
            # Returning to kill the thread.
        except:
            return


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


def create_vnf_image(vnf_property_dict=None, config=None, ovf_adapt_fn=None):
    """

    :param ovf_adapt_fn:
    :param config:
    :param vnf_property_dict:
    :return:
    """

    # populate ova setting
    if ovf_adapt_fn is not None:
        logging.info("OVF adaptation callback.")
        ovf_adapt_fn(vnf_property_dict=vnf_property_dict)

    # find host where we want deploy VM
    objview = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True)
    esxi_hosts = objview.view

    # we search for target ESXi system in vCenter inventory
    target_host = None
    for esxi_host in esxi_hosts:
        if vnf_property_dict['target_host'] == esxi_host.name:
            target_host = esxi_host

    # if we didn't found target host
    if target_host is None:
        logging.warning("Target host {0} not found".format(vnf_property_dict['target_host']))
        return False

    # we choose largest storage on target esxi host
    target_datastore = {'freeSpace': 0}
    for ds in target_host.datastore:
        storage_data = ds.summary
        if storage_data.type == 'VMFS':
            if target_datastore['freeSpace'] < storage_data.freeSpace:
                target_datastore['datastore'] = storage_data.datastore
                target_datastore['name'] = storage_data.name

    vim_dict = {'datacenter_name': 'Datacenter',
                'cluster_name': 'uCPE',
                'datastore_name': target_datastore['name']}
    objects = get_objects(si=si, vim_dict=vim_dict)

    # read generate OVF file
    ovffilename = "{0}/{1}/{2}".format(vnf_property_dict['image_dir'],
                                       vnf_property_dict['target_host'],
                                       vnf_property_dict['ovf_filename'])

    # populate list of vmdk files
    path_to_vmdk = vnf_property_dict['vnf_dir'] + '/.'
    files = [f for f in os.listdir(path_to_vmdk) if re.match(r'[a-zA-z0-9]+.*\.vmdk', f)]
    if files is None or len(files) == 0:
        logging.warning("Image not found in {0}.".format(path_to_vmdk))
        return False

    ovfd = get_ovf_descriptor(ovffilename)

    # generate name and create import spec
    manager = si.content.ovfManager
    uuid = get_uuidbyip(vnf_property_dict['target_host'])
    vm_name = "{0}.{1}".format("velo-edge-vc", uuid)

    # for esxi_host in esxi_hosts:
    #     if vnf_property_dict['target_host'] == esxi_host.name:
    #         print(esxi_host.config.network)

    # print(get_obj(content, [vim.Network], 'VeloOutside'))

    outside = get_obj(content, [vim.Network], 'VeloOutside')
    if outside is None:
        logging.debug("Port group VeloOutside not present")
    inside = get_obj(content, [vim.Network], 'VeloInside')
    if inside is None:
        logging.debug("Port group VeloInside not present")

    # print(outside)
    netmap = [vim.OvfManager.NetworkMapping(name="GE1", network=inside),
              vim.OvfManager.NetworkMapping(name="GE2", network=inside),
              vim.OvfManager.NetworkMapping(name="GE3", network=outside),
              vim.OvfManager.NetworkMapping(name="GE4", network=outside),
              vim.OvfManager.NetworkMapping(name="GE5", network=inside),
              vim.OvfManager.NetworkMapping(name="GE6", network=inside)]

    spec_params = vim.OvfManager.CreateImportSpecParams(entityName=vm_name, ipAllocationPolicy='fixedPolicy',
                                                        networkMapping=netmap, ipProtocol='IPv4')
    import_spec = manager.CreateImportSpec(ovfd,
                                           objects["resource pool"],
                                           objects['datastore'],
                                           spec_params)

    # in case OVF invalid import_sec will should have error flag.
    if len(import_spec.error) == 0:
        logging.info("OVF import is validated.")
    else:
        logging.info("Incorrect ovf format.  vCenter rejected proposed OVF.")
        print(import_spec.error)
        return False
    #
    lease = objects["resource pool"].ImportVApp(import_spec.importSpec,
                                                objects["datacenter"].vmFolder,
                                                target_host)

    logging.info("Creating lease object and uploading ovf.")
    while True:
        if lease.state == vim.HttpNfcLease.State.ready:
            keepalive_thread = Thread(target=keep_lease_alive, args=(lease,))
            keepalive_thread.start()

            for deviceUrl in lease.info.deviceUrl:
                url = deviceUrl.url.replace('*', config['vcenter']['ip'])
                fileItem = list(filter(lambda x: x.deviceId == deviceUrl.importKey, import_spec.fileItem))[0]

                vmdkfilename = "{0}/{1}".format(vnf_property_dict['vnf_dir'], fileItem.path)
                imgfd = get_ovf_descriptor(vmdkfilename)
                imgfd_size = os.stat(vmdkfilename)
                logging.info("Uploading file {0} file size {1}".format(vmdkfilename, imgfd_size.st_size))
                logging.info("Target endpoint {0}".format(url))
                headers = {"Content-length": imgfd_size.st_size}
                req = urllib2.Request(url, imgfd, headers)
                response = urllib2.urlopen(req, context=context)
                returncode = response.getcode()
                if 200 <= returncode < 300:
                    logging.info("OVA successfully uploaded.")

            lease.HttpNfcLeaseComplete()
            keepalive_thread.join()

            logging.info("OVF uploaded - changing power state of VNF.")
            vnf = find_vnf(vnf_property_dict=vnf_property_dict, name=vm_name)
            provision(vnf)

            return True
        elif lease.state == vim.HttpNfcLease.State.error:
            logging.info("Lease error: %s" % lease.error)
            break


def find_vnf(vnf_property_dict=None, name=None):
    """

    Function searches VNF in vim.HostSystem.

    :param name: optional parameter of VNF name that we search
    :param vnf_property_dict: should contains target_host key that
                              point to hostname where we search VNF.
    :return: vm object
    """
    all_esxi_hosts = get_all_objs(content, [vim.HostSystem])
    for h in all_esxi_hosts:
        # find target host by hostname
        if vnf_property_dict['target_host'] in h.name:
            # find VM and power on.
            for vm in h.vm:
                if name is not None and name in vm.name:
                    logging.info("VNF -> {0} in a system.".format(name))
                    return vm
                if vnf_property_dict['vnf_default_name'] in vm.name:
                    logging.info("VNF -> {0} in a system.".format(name))
                    return vm
    return None


def callback(vnf_property_dict=None, config=None, ovf_adapt_fn=None):
    """

    Main callback.  It first check if VNF already on boarded and if it is
    it boot is up.

    Otherwise we push a new VNF to a target host.
    vnf_property_dict must contain 'target_host' that indicates where
    want to deploy a VNF.

    ovf_adapt_fn is call back that caller might call in case caller need
    Populate cutome ovf attributes. ( password / IP / default network)


    :return:
    """

    vnf = find_vnf(vnf_property_dict=vnf_property_dict)
    if vnf is None:
        create_vnf_image(vnf_property_dict=vnf_property_dict, config=config, ovf_adapt_fn=ovf_adapt_fn)
    else:
        logging.info("Changing power state for VNF.")
        provision(vnf)


def delHostSwitch(host, vswitchName):
    vswitch_spec = pyVmomi.vim.host.VirtualSwitch.Specification()
    host.configManager.networkSystem.DelVirtualSwitch(vswitchName)


def addHostSwitch(host, vswitchName, pnicName=None):
    """

    Adds a new local switch to a target ESXi host.

    :param pnicName:
    :param vswitchName:
    :param host:

    :type host: basestring
    :type pnicName: basestring
    :type vswitchName: basestring
    """

    pnic = None
    pnic_found = False
    # find pnic on host device
    for _pnic in host.config.network.pnic:
        if pnicName == _pnic.device:
            pnic = _pnic
            break

    # TODO at list
    if pnic is not None:
        pnic_list = [pnic]
        vswitch_spec = pyVmomi.vim.host.VirtualSwitch.Specification()
        vswitch_spec.numPorts = 16
        vswitch_spec.mtu = 1500
        vswitch_spec.bridge = vim.host.VirtualSwitch.BondBridge(nicDevice=[pnic.device])
        host.configManager.networkSystem.AddVirtualSwitch(vswitchName, vswitch_spec)
    else:
        logging.warning("Error pnic {0} not found on the target host.".format(pnicName))


def AddHostPortgroup(host, vswitchName, portgroupName, vlanId):
    """

    :param vswitchName:
    :param portgroupName:
    :param vlanId:
    :return:
    """
    portgroup_spec = pyVmomi.vim.host.PortGroup.Specification()
    portgroup_spec.vswitchName = vswitchName
    portgroup_spec.name = portgroupName
    portgroup_spec.vlanId = int(vlanId)
    network_policy = pyVmomi.vim.host.NetworkPolicy()
    network_policy.security = pyVmomi.vim.host.NetworkPolicy.SecurityPolicy()
    network_policy.security.allowPromiscuous = True
    network_policy.security.macChanges = False
    network_policy.security.forgedTransmits = False
    portgroup_spec.policy = network_policy

    host.configManager.networkSystem.AddPortGroup(portgroup_spec)


def get_uuidbyip(name):
    """

    Returns esxi uuid by given name in vCenter inventory.

    :type name: basestring
    :return:
    """
    if name is None or not name:
        return None

    # find host where we want deploy VM
    objview = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.HostSystem], True)
    esxi_hosts = objview.view

    for esxi_host in esxi_hosts:
        if name in esxi_host.name:
            return esxi_host.hardware.systemInfo.uuid

    return None


def find_vswitch(switch_name=None, esxi_hostname=None):
    """

    :param switch_name:
    :param esxi_hostname:
    :type switch_name: basestring
    :type esxi_hostname: basestring
    :return: None or switch object
    """

    esxi_host = get_esxi_host(esxi_hostname)
    if esxi_host is not None:
        for v_switch in esxi_host.config.network.vswitch:
            if v_switch.name == switch_name:
                return v_switch

    return None


def find_port_group(switch_name=None, esxi_host=None, pg_name=None):
    """

    Find port group on given ESXi host and vSwitch.

    :param switch_name:
    :param esxi_host:
    :param pg_name:
    :type switch_name: basestring
    :type esxi_host: vim.HostSystem
    :type pg_name: basestring
    :return: None or switch object
    """

    v_switch = find_vswitch(switch_name=switch_name, esxi_hostname=esxi_host.name)
    if v_switch is not None:
        for pg in esxi_host.config.network.portgroup:
            if pg.spec.name == pg_name:
                return pg

    return None


def create_switches(vnf_property_dict=None, switch_list=None):
    """

    Function creates a local switch on target ESXi host

    :param vnf_property_dict:
    :param switch_list:
    :return:
    """

    logging.info("Creating vswitches on target host.")
    esxi_host = get_esxi_host(target_host=vnf_property_dict['target_host'])
    if esxi_host is None:
        logging.debug("Can't find target esxi host.")
        return False

    sw_is_added = False
    pg_is_added = False

    # for every switch in the list we create respected switch on esxi host
    for sw_dict in switch_list:
        sw_is_added = False
        switch_add_retry = 0
        while sw_is_added is False:
            if switch_add_retry == 3:
                break
            # search for switch
            if find_vswitch(sw_dict['vswitch'], vnf_property_dict['target_host']) is not None:
                logging.info("Found vswitch {0}".format(sw_dict['vswitch']))
                sw_is_added = True
            else:
                logging.info("Creating vswitch {0} pnic {1}".format(sw_dict['vswitch'], sw_dict['pnic']))
                addHostSwitch(esxi_host, sw_dict['vswitch'], pnicName=sw_dict['pnic'])
                if find_vswitch(sw_dict['vswitch']) is not None:
                    time.sleep(1)
                else:
                    logging.info("Found vswitch {0}".format(sw_dict['vswitch']))
                    sw_is_added = True
            # increment retry
            switch_add_retry += 1

    # we don't care about speed most important correctness so no timeing issues
    for sw_dict in switch_list:
        for switch in esxi_host.config.network.vswitch:
            # find target switch
            if switch.name == sw_dict['vswitch']:
                pg_add_retry = 0
                pg_is_added = False
                while pg_is_added is False:
                    if pg_add_retry == 5:
                        break
                    if find_port_group(sw_dict['vswitch'], esxi_host, sw_dict['port-group-name']) is not None:
                        logging.info("Found port group {0}".format(sw_dict['port-group-name']))
                        pg_is_added = True
                    else:
                        logging.info("Adding new port group {0} to switch {1}".format(sw_dict['port-group-name'],
                                                                                      sw_dict['vswitch']))
                        AddHostPortgroup(esxi_host, sw_dict['vswitch'],
                                         sw_dict['port-group-name'],
                                         sw_dict['vlan_id'])
                        # we add / check and if not there we sleep and re-check again
                        if find_port_group(sw_dict['vswitch'], esxi_host, sw_dict['port-group-name']) is not None:
                            time.sleep(1)
                        else:
                            logging.info("Found port group {0}".format(sw_dict['port-group-name']))
                            pg_is_added = True
                        # increment retry
                        pg_add_retry += 1

    if pg_is_added is True and sw_is_added is True:
        return True

    return False


def get_activation_key(config=None, edgeName=None):
    """

    Function leverage Velo Cloud IP and requests activation key.

    :param config:
    :param edgeName:
    :return:
    :return:
    """

    activation_key = None

    client = ztp.velocloud.ApiClient(host=config['vce-vco'])
    client.authenticate(config['vco-username'], config['vco-password'], operator=False)
    api = ztp.velocloud.AllApi(client)

    try:
        params = {"enterpriseId": config['enterpriseId']}
        res = api.enterpriseGetEnterpriseConfigurations(params)
        for profile in res:
            if config['profile-name'] in profile.name:
                profileId = profile.id
                params = {"enterpriseId": config['enterpriseId'],
                          "name": edgeName,
                          "description": "Onboarded automatically",
                          "modelNumber": "virtual",
                          "generate_certificate": False,
                          "configurationId": profileId}

                res = api.edgeEdgeProvision(params)
                return res

    except ApiException as e:
        print(e)

    return activation_key


def main_loop(ch, method, properties, body):
    """

    Main execution loop.  Function enter a main loop upo

    :return:
    """

    logging.info("Starting vnf on-boarding task for a host {0}".format(body))
    hostname = body

    veloconfig = config['velocloud']             # configuration section for VeloCloud
    vnf_networks = config['vnf-network']         # configuration section for esxi
    skip_queue = False

    # check that all directories are valid
    if os.path.isdir(veloconfig['image-dir']) is False:
        logging.warning("Error: '{0}' Image dir is invalid path {0}".format(veloconfig['image-dir']))
        skip_queue = True
    if os.path.isdir(veloconfig['vnf-dir']) is False:
        logging.warning("Error: '{0}' vnf dir is invalid path {0}".format(veloconfig['vnf-dir']))
        skip_queue = True

    # remove last slash in case client indicate it
    if veloconfig['image-dir'].endswith('\\'):
        veloconfig['image-dir'] = veloconfig['image-dir'][:-1]

    # remove last slash in case client indicate it
    if veloconfig['vnf-dir'].endswith('\\'):
        veloconfig['vnf-dir'] = veloconfig['vnf-dir'][:-1]

    try:
        # just basic check that hostname is valid
        host_name = socket.gethostbyname(veloconfig['vce-vco'])
        if host_name is None or len(host_name) == 0:
            logging.warning("Invalid VCO hostname")
    except socket.gaierror as e:
        print("Exception: wrong VCO hostname. {0}".format(e.message))

    if skip_queue is False:
        try:
            logging.info("Requesting activation key from vco {0}.".format(veloconfig['vce-vco']))
            activation_key = get_activation_key(config=veloconfig, edgeName=hostname)
            if activation_key is None:
                logging.warning("Failed retrieve activation key from vco {0}.".format(veloconfig['vce-vco']))
                return False
            else:
                logging.warning("Activation key for velo cloud edge VNF {0}.".format(activation_key.activationKey))

            # we pack all properties in single dict
            vnf_property_dict = {'ovf_filename': veloconfig['ovf-filename'],
                                 'vnf_dir': veloconfig['vnf-dir'],
                                 'image_dir': veloconfig['image-dir'],
                                 'target_host': hostname,
                                 'activation_code': activation_key.activationKey,
                                 'vce.vco': veloconfig['vce-vco'],
                                 'password': veloconfig['vnf-default-password'],
                                 'vnf_default_name': veloconfig['vnf-default-name']}

            logging.info("Target host system {0} {1}".format(vnf_property_dict['target_host'],
                                                             get_uuidbyip(vnf_property_dict['target_host'])))

            create_switches(vnf_property_dict=vnf_property_dict, switch_list=vnf_networks['topology'])
            callback(vnf_property_dict=vnf_property_dict, config=config, ovf_adapt_fn=populate_ova)

        except TypeError as e:
            print(e)
            print("Exception wrong type. {0}".format(e.message))
        except KeyError as e:
            print(e)
            print("Exception key not found {0}".format(e.message))


def validate_config():

    if 'ampq' not in config:
        logging.info("Error: ampq is mandatory configuration section. Please check yaml file.")
        return False

    if 'username' not in config['ampq']:
        logging.info("Error: username is mandatory configuration section. Please check yaml file.")
        return False

    if 'password' not in config['ampq']:
        logging.info("Error: password is mandatory configuration section. Please check yaml file.")
        return False

    if 'hostname' not in config['ampq']:
        logging.info("Error: hostname is mandatory configuration section. Please check yaml file.")
        return False

    veloconfig = config['velocloud']

    # mandatory configuration elements
    mandatory_fields = ["vce-vco",
                        "ovf-filename",
                        "vnf-dir",
                        "image-dir",
                        "vnf-default-password",
                        "vnf-default-name",
                        "profile-name",
                        "enterpriseId",
                        "vco-username",
                        "vco-password"]

    for field in mandatory_fields:
        if field not in veloconfig:
            logging.info("Error: '{0}' is mandatory configuration field. check default.yaml file.".format(field))
            return False

    return True


if __name__ == "__main__":
    """
    
    Main entry for VNF on boarding listner.
    
    """

    if validate_config() is True:
        credentials = pika.PlainCredentials(config['ampq']['username'], config['ampq']['password'])
        connection = pika.BlockingConnection(pika.ConnectionParameters(host=config['ampq']['hostname'],
                                                                       credentials=credentials))
        logging.getLogger("pika").setLevel(logging.WARNING)
        channel = connection.channel()
        channel.queue_declare(queue='vnfonboarding')
        channel.basic_consume(main_loop, queue='vnfonboarding', no_ack=True)
        logging.info('Waiting for VNF on boarding request. To stop press CTRL+C')
        try:
            channel.start_consuming()
        except KeyboardInterrupt:
            channel.stop_consuming()

        connection.close()

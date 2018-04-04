#!/usr/bin/python
"""
    ENS tester provide automation tool to do regresion test.

    Apps reads configuration from tester-config.yaml and runs each respected test.

    Each test described in separate yaml file.

    tester-config.yaml

    tester:
    - test:     1
      name:     "tc-1.1"
      test-scenario:   "/home/trex/v2.36/automation/trex_control_plane/stl/examples.mb/tc-1.1.yaml"
    - test:     2
      name:     "tc-1.1-unidirection"
      test-scenario:   "/home/trex/v2.36/automation/trex_control_plane/stl/examples.mb/tc-1.1-unidirection.yaml"
    - test:     3
      name:     "tc-2.1"
      test-scenario:   "/home/trex/v2.36/automation/trex_control_plane/stl/examples.mb/imix.yaml"

    Example below.

    Single unidirectional stream generated from port 0 and should be received to a same port.
    In this example same port receives a traffic in case we have separate ports ingress can be [0] egress [1]
    The ingress and egress array elements.  So if we want send from two port we can indicate [0, 1]

    In this example tester connected via 40Gbe so we set bw 4000.

    Packet size indicate list of packet size we wish to test.
            In this example it 492 = 512.  L3 size 576 and 1004 for 1024 size

    rate auto indicates that initial value will calucalate maximum pps from port_bw
    since it single flow and ENS can handle more than 10G we need reduce based on 10Gbe

    We can either change port_bw or reduce percent so in this case it set 25%

    Adaptive indicate that if max pps will failure script will reduce pps aggregate pps.

    Iteration indicate how many time tester will reduce a rate if all.

tester:
    - test:     1
      name:     tc-1.1
      test-result:   /home/trex/Results/tc-1.1.txt
      max-iteration: 8
      max-duration:  60
      acceptable-loss: 0.001
      adaptive: True                # indicate if we fail a test we drop a rate to next pps
      port_bw:  4000                # port bandwidth
      packet-size:
          - size: 492
          - size: 1024
      flows:
          - flow:   first-flow
            srcmac: "3C:FD:FE:B5:27:88"
            dstmac: "00:50:56:A5:0A:3A"
            srcip:  1.1.1.1
            dstip:  2.1.1.2
            srcport: 1025
            dstport: 12
            vlan:   653
            egress_port: [0]              # egress port id or list of ports [0, 1]
            ingress_port: [0]             # ingress port id or list of ports [0, 1]
            rate: auto                    # it in ingress direction  support keyword auto than we calculate from reference bandwith
            percent: 25                   # 50 percent in one direction auto indicate calculate max pps for given packet size / 2


    Mustafa Bayramov
    mbayramov@vmware.com
"""
import ssl
import sys
import os
import yaml
from dpdk_environment import setup_environment
from dpdk_environment import teardown_environment

from decimal import *
import pprint

try:
    import stl_path
    from trex_stl_lib.api import *
except ImportError:
    print "trex not installed."
    # raise ImportError('<any message you want here>')

from prettytable import PrettyTable
import xlsxwriter

import time
import json
import sys
import copy

import re
from operator import truediv
import string

import re
from operator import truediv
import operator

import logging

dir_path = os.path.dirname(os.path.realpath(__file__))
log_path = dir_path
log_filename = "vmware"

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler("{0}/{1}.log".format(log_path, log_filename)),
        logging.StreamHandler()
    ],
    level=logging.INFO)


class bcolors:
    """
     colors used for console output
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


MPPS = 1000000.00  # pps reference
GPPS = 1000000000.00  # gpss reference

RATE = 1000000000  # bw reference
L1_HDR_SIZE = 20  # L1 header for example for 64 byte on the wire 84 byte.


# 64 byte L2 header + 20 byte L1.


def maxpps(packet_size, percent, interface_rate):
    """
    Calculates target pps for a given interface rate.

    :param packet_size:     target packet size. ( 64 / 128 ... )
    :param percent:         percent from line rate (10, 20 ... 100)
    :param interface_rate:  interface rate (1000 for 10Gbe , 4000 for 40Gbe etc)
    :return: target pps
    """
    l1size = (packet_size + L1_HDR_SIZE) * 8
    return truediv((RATE * interface_rate / 100), l1size) * truediv(percent, 100)


def packet_dst_tostring(flow):
    """
    Reads either destination start ip and destination end ip or single source ip address
    from flow configuration section.

    :param flow:
    :return:
    """
    try:
        # TODO parse list
        if 'ranges' in flow:
            ip_range = flow['ranges'][0]
            return "{0} - {1}".format(ip_range['dst-start'], ip_range['dst-end'])
        else:
            return flow['dstip']
    except KeyError as e:
        print "Mandatory key not present. Check configuration yaml file."
        print "".format(e)
    except TypeError as e:
        print "".format(e)


def packet_src_tostring(flow):
    """
    Reads either source start ip and source end ip or single source ip address
    from flow configuration section.

    :param flow:
    :return:
    """
    # TODO parse list
    try:
        if 'ranges' in flow:
            ip_range = flow['ranges'][0]
            return "{0} - {1}".format(ip_range['src-start'], ip_range['src-end'])
        else:
            return flow['srcip']
    except KeyError as e:
        print "Mandatory key not present. Check configuration yaml file."
        print "".format(e)
    except TypeError as e:
        print "".format(e)


def append_flow(flow_table=None, flow=None, flow_rate=None, header_size=0, payload_size=0):
    """
    Function appends single flow record to flow table. flow table used
    used for console output.

    :param flow_table:    flow table used for console output
    :param flow:          test flow
    :param flow_rate:     flow target rate
    :param header_size:    L2 frame size
    :param payload_size:  payload size.
    :return: nothing
    """

    if 'auto' in flow['rate-mode'] and 'percent' in flow:
        flow_type = "Auto {0}%".format(str(flow['percent']))
    elif 'fixed' in flow['rate-mode']:
        flow_type = "Fixed pps"
    else:
        flow_type = ""

    try:
        if 'vlan' in flow:
            vlan_detail = flow['vlan']
        else
            vlan_detail = "untagged"

        # TODO move formatted to configuration file
        flow_table.add_row(["{:,}".format(flow_rate),
                            flow['id'],
                            flow_type,
                            flow['srcmac'],
                            flow['dstmac'],
                            packet_src_tostring(flow),
                            packet_dst_tostring(flow),
                            flow['srcport'],
                            flow['dstport'],
                            vlan_detail,
                            header_size,
                            payload_size,
                            header_size + payload_size,
                            flow['max-pps']])
    except KeyError as e:
        print "Mandatory key not present. Check configuration yaml file."
        print "".format(e)
    except TypeError:
        print ""


def generate_payload(length):
    """
    Generate payload for test flow with alphabet
    :param length:
    :return:
    """
    word = ''
    alphabet_size = len(string.letters)
    for i in range(length):
        word += string.letters[(i % alphabet_size)]
    return word


def save_as_cvs_report(test_result=None, result_filename=None, passed_only=False, stats_filter=None, verbose=False):
    """

    Create cvs report for test and saves to a file.
    The value populated based on stats filter dict.

    :param test_result:  test_result must hold a result for test
    :param result_filename: a valid path to a file
    :param passed_only: indicate to generate report only for a flow that passed test.
    :param stats_filter indicate what values client wish to save to a file.
    :param
    :return: nothing
    """
    if verbose is True:
        print "Saving result to a file {0}".format(result_filename)

    result_file = open(result_filename, "a")

    #  keys - rx_bps, latency_min, rx_pps, jitter, ingress_port, latency_max, port_tx,
    #  iteration, flow_status, packet_size, egress_port, tx_bps, tx_pps, port_rx,
    #  average_lost, flow_id, latency_avg
    if stats_filter is None or len(stats_filter) == 0:
        _filter = ['iteration', 'flow_id', 'tx_pps', 'rx_pps', 'tx_bps', 'rx_bps', 'flow_status']
    else:
        _filter = stats_filter

    if 'flow_status' not in _filter:
        _filter.append('flow_status')

    try:
        for test_case in test_result:
            filtered_dict = {k: v for k, v in test_case.items() if k in _filter}
            for index, key in enumerate(_filter):
                if (passed_only is True and 'Pass' in filtered_dict['flow_status']) or passed_only is False:
                    if key in filtered_dict:
                        result_file.write('{0}'.format(filtered_dict[key]))
                        if index != len(_filter) - 1:
                            result_file.write(',')
                    result_file.write('\n')
    except KeyError as e:
        print "Mandatory key not present. Check configuration yaml file."
        print "".format(e)
    except TypeError:
        print ""
    except IOError as e:
        print "IO error"
        print "".format(e)

    result_file.write("\n")
    result_file.close()


def save_as_excel_report(test_result=None, result_filename=None, passed_only=False, stats_filter=None, verbose=False):
    """

    Function generates an excel report and saves a result to a provided file name

    :param test_result: list of dict that contains test result data
    :param result_filename: excel file name.
    :param passed_only: indicate to generate report only for a flow that passed test.
    :param stats_filter
    :param verbose
    :return: True otherwise False ( can't create fail / key error etc)
    """

    if verbose is True:
        print "Saving result to a excel file {0}".format(result_filename)

    try:
            workbook = xlsxwriter.Workbook(result_filename)
            worksheet = workbook.add_worksheet()
    except IOError as e:
        print "IO error"
        print "".format(e)
        return False

    # headings
    headings = ['iteration', 'flow id', 'packet size (byte)', 'avg lost (pkt)', 'flow pkt-tx', 'flow pkt-rx',
                'status', 'egress port', 'ingres port', 'Port Tx (Mpps)', 'Port Rx (Mpps)', 'Port Tx (Gbps)',
                'Port Rx (Gbps)', 'lat min', 'lat max', 'lat avg', 'jitter', 'aggregate pps']

    bold = workbook.add_format({'bold': 1, 'font_size': 14, 'align': 'center'})
    row = 1
    col = 0

    for idx, val in enumerate(headings):
        worksheet.set_column(idx, idx, len(headings[idx]) + 4)

    worksheet.write_row('A1', headings, bold)

    # by default we sort by iteration and flow_id
    sorted_test_result = sorted(test_result, key=lambda k: (k['iteration'], k['flow_id']))
    cell_format = workbook.add_format({'font_size': 14, 'align': 'center'})
    cell_format2 = workbook.add_format({'font_size': 14, 'align': 'center'})
    cell_format3 = workbook.add_format({'font_size': 14, 'align': 'center'})
    cell_format2.set_num_format('#,##0')
    cell_format3.set_num_format('0.000')

    if stats_filter is None or len(stats_filter) == 0:
        # default dict_ filter includes all keys
        _filter = ['iteration', 'flow_id', 'packet_size', 'average_lost',
                   'port_rx', 'port_tx', 'flow_status', 'ingress_port', 'egress_port',
                   'tx_pps', 'rx_pps' 'tx_bps', 'rx_bps', 'latency_min',
                   'latency_max', 'latency_avg', 'jitter']
    else:
        _filter = stats_filter

    # we always append flow status
    if 'flow_status' not in _filter:
        _filter.append('flow_status')

    try:
        for flow_record in sorted_test_result:
            if 'flow_status' in flow_record:
                if (passed_only is True and 'Pass' in flow_record['flow_status']) or passed_only is False:
                    # set row format
                    worksheet.set_row(row, None, cell_format)
                    worksheet.write_number(row, col, flow_record['iteration'])
                    worksheet.write_number(row, col + 1, flow_record['flow_id'])
                    worksheet.write_number(row, col + 2, flow_record['packet_size'], )
                    worksheet.write(row, col + 3, flow_record['average_lost'], cell_format3)
                    worksheet.write_number(row, col + 4, flow_record['port_rx'], cell_format2)
                    worksheet.write_number(row, col + 5, flow_record['port_tx'], cell_format2)
                    worksheet.write(row, col + 6, flow_record['flow_status'])
                    worksheet.write_string(row, col + 7, ",".join(flow_record['ingress_port']))
                    worksheet.write_string(row, col + 8, ",".join(flow_record['egress_port']))
                    worksheet.write_number(row, col + 9, flow_record['tx_pps'], cell_format2)
                    worksheet.write_number(row, col + 10, flow_record['rx_pps'], cell_format2)
                    worksheet.write_number(row, col + 11, flow_record['tx_bps'])
                    worksheet.write_number(row, col + 12, flow_record['rx_bps'])
                    worksheet.write_number(row, col + 13, flow_record['latency_min'])
                    worksheet.write_number(row, col + 14, flow_record['latency_max'])
                    worksheet.write_number(row, col + 15, flow_record['latency_avg'], cell_format3)
                    worksheet.write_number(row, col + 16, flow_record['jitter'])
                    worksheet.write_number(row, col + 17, flow_record['rx_pps'] + flow_record['rx_pps'], cell_format2)
                    row += 1
    #
    except TypeError:
        print ""
    except KeyError as e:
        print "undefined key"

    workbook.close()

    return True


def get_flowbyid(flow_table=None, flow_id=0):
    """
    Returns flow from flow table lookup done based on flow_id

    :param flow_table:
    :param flow_id:
    :return:
    """
    for flow in flow_table:
        if flow_id == flow['id']:
            return flow


def truncate(f, n):
    """

    Truncates/pads a float f to n decimal places without rounding

    :param f:
    :param n:
    :return:
    """
    s = '%.12f' % f
    i, p, d = s.partition('.')
    return '.'.join([i, (d + '0' * n)[:n]])


def console_report(console_output_tlb=None, generic_stats_tlb=None):
    """

    Prints test flow result to console.

    :param console_output_tlb:
    :param generic_stats_tlb:
    :return: nothing
    """
    try:
        for test_run in generic_stats_tlb:
            test_result_entry = [test_run['iteration'],
                                 test_run['flow_id'],
                                 test_run['packet_size'],
                                 round(Decimal(test_run['average_lost']), 5),
                                 test_run['port_rx'],
                                 test_run['port_tx'],
                                 test_run['flow_status'],
                                 test_run['ingress_port'],
                                 test_run['egress_port'],
                                 test_run['tx_pps'],
                                 test_run['rx_pps'],
                                 test_run['tx_bps'],
                                 test_run['rx_bps'],
                                 test_run['latency_min'],
                                 test_run['latency_max'],
                                 round(Decimal(test_run['latency_avg']), 2),
                                 test_run['jitter'],
                                 test_run['aggregate_pps']]
            console_output_tlb.add_row(test_result_entry)
    except TypeError as e:
        print "Can't build console output."
        print "".format(e)


def get_latency_stats(stats, flow_id):
    """

    Return latency statics if present from stats dict

    :param stats:
    :param flow_id:
    :return:
    """

    latency_min_flt = 0
    latency_max_flt = 0
    latency_avg_flt = 0
    jitter_flt = 0

    try:
        if 'latency' in stats:
            latency_stats = stats['latency']
            if flow_id in latency_stats:
                latency_stat = latency_stats[flow_id]['latency']
                if 'jitter' in latency_stat:
                    jitter_flt = latency_stat['jitter']
                if 'total_min' in latency_stat:
                    latency_min_flt = latency_stat['total_min']
                if 'total_max' in latency_stat:
                    latency_max_flt = latency_stat['total_max']
                if 'average' in latency_stat:
                    latency_avg_flt = latency_stat['average']

    except TypeError as e:
        print ""
        print "".format(e)
    except KeyError as e:
        print ""
        print "".format(e)

    return {'latency_min': latency_min_flt, 'latency_max': latency_max_flt,
            'latency_avg': latency_avg_flt, 'jitter': jitter_flt}


def get_total_stats(stats):
    """

    Returns total flow statics if present from stats dict

    :param stats:
    :return:
    """

    tx_pps = 0
    rx_pps = 0
    tx_bps = 0
    rx_bps = 0
    ierrors = 0
    oerrors = 0
    l1_rx_bps = 0
    l1_tx_bbs = 0

    try:
        if 'total' in stats:
            total_stats = stats['total']
            tx_pps_dec = Decimal(total_stats['tx_pps'])
            rx_pps_dec = Decimal(total_stats['rx_pps'])
            tx_pps = round(tx_pps_dec, 0)
            rx_pps = round(rx_pps_dec, 0)
            tx_bps = truediv(float(total_stats['tx_bps']), GPPS)
            rx_bps = truediv(float(total_stats['rx_bps']), GPPS)
            ierrors = total_stats['ierrors']
            oerrors = total_stats['oerrors']
            l1_rx_bps = total_stats['rx_bps_L1']
            l1_tx_bbs = total_stats['tx_bps_L1']

    except TypeError:
        print ""
    except KeyError as e:
        print ""
        print "".format(e)

    return {'tx_pps': tx_pps, 'rx_pps': rx_pps,
            'tx_bps': tx_bps, 'rx_bps': rx_bps,
            'ierrors': ierrors, 'oerrors': oerrors,
            'l1_rx_bps': l1_rx_bps, "l1_tx_bbs": l1_tx_bbs}


def append_flow_result(test_results=None, generic_table=None):
    """

    Prints test flow result to console.

    :param generic_table:
    :param test_results:
    :return: nothing
    """

    all_stats = test_results['stats']
    flow_stats = test_results['flow_stats']
    flow_table = test_results['flows']

    for flow_stat in flow_stats:

        flow_status = "Failed"
        if flow_stat['status'] is True:
            flow_status = "Pass"

        for port in flow_stat['egress_ports']:
            egress_ports = ','.join(map(str, flow_stat['egress_ports']))

            latency_stats = get_latency_stats(all_stats, flow_stat['flow_id'])
            total_stats = get_total_stats(all_stats)
            flow = get_flowbyid(flow_table, flow_stat['flow_id'])

            flow_dict = {'iteration': test_results['iteration'],
                         'flow_id': flow_stat['flow_id'],
                         'packet_size': flow['packet-size'],
                         'average_lost': flow_stat['average_lost'],
                         'port_rx': flow_stat['port_rx'],
                         'port_tx': flow_stat['port_tx'],
                         'flow_status': flow_status,
                         'ingress_port': str(port),
                         'egress_port': egress_ports,
                         'aggregate_pps': test_results['aggregate_pps']}

            # add total and latency stats and append to a list
            flow_dict.update(total_stats)
            flow_dict.update(latency_stats)

            generic_table.append(flow_dict)


def calculate_lost(tx, rx):
    """
    Returns frame lost percentage.

    :param tx: number of frame send
    :param rx: number of frame received
    :return: percentage of lost.
    """
    if rx == 0 or tx == 0:
        return 100

    frame_lost = abs((tx - rx) / rx * 100)
#    print " tx {0} rx {1} loss {2}".format(frame_lost)
    return frame_lost


def run(stlclient, stream_list, test_scenario, verbose=False):
    """
    Function takes list of stream list and runs all in one shoot.
    The length of a test dictated by max-duration for entire test scenario.

    :param stlclient:   connection to a tester
    :param stream_list: list of streams that part of single test scenario
    :param test_scenario:  test plan
    :param verbose
    :return:
    """

    # TODO Fix that for multi port case
    stlclient.reset(ports=[0, 1])

    # add streams to ports
    egress_ports = []
    ingress_ports = []
    aggregate_rate = 0

    for stream in stream_list:
        # append all egress ports to a list and ingress port
        egress_ports += stream['egress_port']
        ingress_ports += stream['ingress_port']
        aggregate_rate += stream['rate']
        # TODO check that aggregate > max pps
        stlclient.add_streams(stream['stream'], ports=stream['ingress_port'])

    # clear the stats before injecting
    stlclient.clear_stats()

    all_ports = list(ingress_ports)
    all_ports.extend(port for port in egress_ports if port not in all_ports)

    # stlclient.start(ports=ingress_ports, mult=target_pps, duration=test_plan['max-duration'])
    stlclient.start(ports=ingress_ports, duration=test_scenario['max-duration'])
    stlclient.wait_on_traffic(ports=all_ports, timeout=2400)

    # read the stats after the test
    stats = stlclient.get_stats(sync_now=True)
    pgid_stats = stlclient.get_pgid_stats()

    if stlclient.get_warnings():
        print "\n\n{0} test had warnings: aggregate pps rate {1} {2}\n\n".format(bcolors.FAIL,
                                                                                 aggregate_rate,
                                                                                 bcolors.ENDC)
        for w in stlclient.get_warnings():
            print "{0} {1} {2}".format(bcolors.FAIL, w, bcolors.ENDC)

    if verbose is True:
        print "{0}Port tx {1} pkt flow rx {2} pkt {3} diff {4}".format(bcolors.OKGREEN,
                                                                       stats[0]["opackets"],
                                                                       stats[0]["ipackets"],
                                                                       stats[0]["opackets"] - stats[0]["ipackets"],
                                                                       bcolors.ENDC)
    is_all_pass = True
    per_flow_stats = []
    flow_list = pgid_stats['flow_stats']
    aggregate_lost = 0
    aggregate_overflow = 0
    for flow_id in flow_list:
        if not str(flow_id).isdigit():
            continue

        #  we get packet  total for each respected flow
        tx_pkts = flow_list[flow_id]['tx_pkts']['total']
        rx_pkts = flow_list[flow_id]['rx_pkts']['total']
        port_tx = float(flow_list[flow_id]['tx_pkts']['total'])
        port_rx = float(flow_list[flow_id]['rx_pkts']['total'])
        # lost a and b
        lost_a = tx_pkts - rx_pkts
        lost_b = rx_pkts - tx_pkts

        is_passed = False

        if verbose is True:
            print "{0}flow tx {1} pkt flow rx {2} pkt, diff {3} pkt {4}".format(bcolors.OKGREEN,
                                                                                tx_pkts,
                                                                                rx_pkts,
                                                                                tx_pkts - rx_pkts,
                                                                                bcolors.ENDC)
        if rx_pkts == 0:
            print "{0}100% lost detected {1}".format(bcolors.FAIL, bcolors.ENDC)
            avg_loss_rate = 100
        elif lost_a == lost_b:
            if verbose is True:
                print "{0}No lost detected {1}".format(bcolors.OKGREEN, bcolors.ENDC)
            is_passed = True
            avg_loss_rate = 0
        else:
            # case one rx > tx
            if port_rx > port_tx:
                # if we received more than we send we need check for how much
                # more and if in acceptable range we don't care.
                rx_overflow = calculate_lost(port_rx, port_tx)
                packet_lost = 0
                if verbose is True:
                    print "{0}Checking for potential rx overflow. rx overflow {1}%" \
                          "{2}".format(bcolors.FAIL, rx_overflow, bcolors.ENDC)
                    if rx_overflow > test_scenario['acceptable-rx-overflow']:
                        print "{0}Error: Potential duplicate packets. " \
                              "Check tester configuration.".format(bcolors.FAIL, bcolors.ENDC)
            # case one tx > rx
            else:
                if verbose is True:
                    print "{0}Calculating lost {1}".format(bcolors.FAIL, bcolors.ENDC)
                # check how much we lost
                packet_lost = calculate_lost(port_tx, port_rx)
                print "{0}Lost {1} lost {2}".format(bcolors.FAIL, packet_lost, bcolors.ENDC)
                rx_overflow = 0

            avg_loss_rate = packet_lost
            aggregate_lost = aggregate_lost + avg_loss_rate
            aggregate_overflow = aggregate_overflow + rx_overflow

            if verbose is True:
                print "{0}Average lost {1} {2}".format(bcolors.FAIL, avg_loss_rate, bcolors.ENDC)

            # check that we have lost in acceptable range
            if Decimal(avg_loss_rate) <= Decimal(test_scenario['acceptable-loss']) \
                    and Decimal(rx_overflow) <= Decimal(test_scenario['acceptable-rx-overflow']):
                if verbose is True:
                    print "{0}Passed test with average lost {1} and " \
                          "rx overflow {2} {3}".format(bcolors.OKGREEN, avg_loss_rate, rx_overflow, bcolors.ENDC)
                is_passed = True
            else:
                # if at least one flow passed than all flow failed.
                is_all_pass = False

        # calculate we passed or not and average lost for each flow
        flow_stats_record = {"flow_id": flow_id, "port_tx": tx_pkts, "port_rx": rx_pkts,
                             "status": is_passed, "average_lost": avg_loss_rate,
                             "ingres_ports": set(ingress_ports), "egress_ports": set(egress_ports)}
        per_flow_stats.append(flow_stats_record)

    # pack result
    flow_stats_dict = {'stats': stats,
                       'flow_stats': per_flow_stats,
                       'allpass': is_all_pass,
                       'aggregate_lost': aggregate_lost,
                       'aggregate_overflow': aggregate_overflow}

    return flow_stats_dict


def run_streams(stlclient, stream_dict=None, test_scenario=None, flow_table=None,
                generic_stats_tlb=None, iteration=None, verbose=False):
    """

    Function runs all streams and populates a result for each test in generic_stats_tlb.

    :param stlclient: a reference to a Trex client
    :param stream_dict: a dictionaries contains stream properties
    :param flow_table: a dictionaries that contains flow table for a test scenario.
    :param test_scenario: a configuration section for entire test scenario.
    :param generic_stats_tlb: a list where we populate all statistic information for each stream.
    :param iteration: current iteration
    :param verbose
    :return:
    """
    # print "{0}Starting generating traffic:{1}".format(bcolors.OKGREEN, bcolors.ENDC)

    if stream_dict is None or flow_table is None:
        return False

    stream_list = stream_dict['streams']
    stream_result = run(stlclient, stream_list, test_scenario, verbose=verbose)
    stream_result['iteration'] = iteration
    stream_result['flows'] = flow_table

    aggregate_pps = 0
    for stream in stream_list:
        aggregate_pps = aggregate_pps + stream['rate']
    stream_result['aggregate_pps'] = aggregate_pps

    # if all flow passed
    append_flow_result(test_results=stream_result, generic_table=generic_stats_tlb)
    if stream_result['allpass'] is True:
        return True

    # TODO aggregate rate cap
    for stream in stream_list:
        # we reduce rate only for auto rate flow
        if stream['isauto'] is True:
            stream['rate'] = stream['rate'] - (stream['rate'] * Decimal(0.05)).to_integral_value()

    for flow in flow_table:
        if 'auto' in flow['rate-mode']:
            # throttle down each flow - reduce stream rate to given percentage
            if verbose is True:
                print "{0}Throttling flow pps from {1}% to {2}%{3}".format(bcolors.FAIL,
                                                                           flow['percent'],
                                                                           flow['percent'] - flow['throttle'],
                                                                           bcolors.ENDC)
            flow['percent'] = flow['percent'] - flow['throttle']

    # if test scenario is adaptive we will reduce percentage for each packet size.
    # so all flow will use new ratio.
    if 'packet-iteration' in test_scenario['test-type'] and test_scenario['adaptive'] is True:
        current_percentage = get_flow_percentage(test_scenario=test_scenario, packet_size=stream_dict['frame_size'])
        if current_percentage > 0:
            new_percentage = current_percentage - stream_dict['throttle']
            if verbose is True:
                print "{0}Throttling flow pps for a packet size {1} byte " \
                      "current {2}% new {3}% {4}".format(bcolors.FAIL, stream_dict['frame_size'],
                                                         current_percentage,
                                                         new_percentage,
                                                         bcolors.ENDC)

                # set new percentage that will trigger re-calculation target pps.
                set_flow_percentage(test_scenario=test_scenario,
                                    packet_size=stream_dict['frame_size'],
                                    percent=new_percentage)

    return False


def validate_scenario(flow=None, test_plan=None):
    """

    Validates configuration for test plan and for each respected test flow.

    :param flow: list of flows
    :param test_plan: configuration section for a test.
    :return: True if all mandatory configuration element are present.
    """
    test_plan_fields = ["name",
                        "test-result",
                        "test-result-format",
                        "max-iteration",
                        "max-duration",
                        "acceptable-loss",
                        "adaptive",
                        "port_bw",
                        "test-type",
                        "acceptable-rx-overflow"]

    flow_fields = ["id", "srcmac", "rate-mode", "dstmac", "egress_port", "ingress_port"]

    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", flow['srcmac'].lower()) is False:
        print "Invalid source mac address."
        return False

    if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", flow['dstmac'].lower()) is False:
        print "Invalid destination mac address."
        return False

    for field in test_plan_fields:
        if field not in test_plan:
            print "{0}Error: \'{1}\' is mandatory field for test " \
                  "plan {2}".format(bcolors.FAIL, field, bcolors.ENDC)
            return False

    for field in flow_fields:
        if field not in flow:
            print "{0}Error: \'{1}\' is mandatory field for test " \
                  "flow {2}".format(bcolors.FAIL, field, bcolors.ENDC)
            return False

    if flow['rate-mode'] is 'auto' and test_plan['adaptive'] is True:
        if 'throttle' not in flow:
            print "{0}Error: \'{1}\' is required field for adaptive test " \
                  "in auto rate mode. {2}".format(bcolors.FAIL, 'throttle', bcolors.ENDC)
            return False

        if 'percent' not in flow:
            print "{0}Error: \'{1}\' is required field for adaptive test " \
                  "in auto rate mode. {2}".format(bcolors.FAIL, 'percent', bcolors.ENDC)
            return False

    if flow['rate-mode'] is 'fixed' and 'stream-rate' not in flow:
        print "{0}Error: \'{1}\' is required field for fixed rate test. " \
              "{2}".format(bcolors.FAIL, 'throttle', bcolors.ENDC)
        return False

    return True


def set_flow_percentage(test_scenario=None, packet_size=0, percent=0):
    """

    Sets a new percentage for a given packet size.
    For example:   We have following packet size list and we need reduce a percentage for packet size 520.

    packet-size:
          - size: 78
            percent: 25
          - size: 138
            percent:  30
          - size: 262
            percent: 60
          - size: 520
            percent: 100
          - size: 1032
            percent: 100


    :param test_scenario:
    :param packet_size:
    :param percent:
    :return:
    """
    if 'packet-size' in test_scenario:
        for packet_size_list in test_scenario['packet-size']:
            if packet_size == packet_size_list['size'] and 'percent' in packet_size_list:
                packet_size_list['percent'] = percent


def get_flow_percentage(test_scenario=None, packet_size=0):
    """

    Gets a flow percentage
    :param test_scenario:
    :param packet_size:
    :return:
    """

    link_percent = 0

    # find percentage value we need use for a given packet size.
    if 'packet-size' in test_scenario:
        for packet_size_list in test_scenario['packet-size']:
            if packet_size == packet_size_list['size'] and 'percent' in packet_size_list:
                link_percent = packet_size_list['percent']

    return link_percent


def calculate_rate(test_scenario=None, flow=None, packet_size=512, verbose=False):
    """

    :param test_scenario:
    :param flow:
    :param packet_size:
    :param verbose
    :return:
    """
    stream_rate = 0

    # each flow can overwrite packet size
    actual_pkt_size = packet_size
    if flow is None:
        return stream_rate

    link_percent = get_flow_percentage(test_scenario, packet_size=packet_size)

    if 'auto' in flow['rate-mode']:
        # in auto mode port_bw is mandatory element since we need use a reference bw
        if 'port_bw' not in test_scenario:
            print "{0}Error: \'{1}\' is mandatory field for auto rate. " \
                  "{2}".format(bcolors.FAIL, 'port_bw', bcolors.ENDC)
            return stream_rate

        # in auto mode percentage mandatory element it either setting for a flow or packet size.
        if link_percent is 0:
            if 'percent' not in flow:
                print "{0}Error: \'{1}\' is mandatory field for auto rate. " \
                      "{2}".format(bcolors.FAIL, 'percent', bcolors.ENDC)
                return stream_rate

            # we set percentage from flow section
            link_percent = flow['percent']

        # calculate pps value based on percentage value.
        stream_rate = long(Decimal(maxpps(packet_size=actual_pkt_size,
                                          percent=link_percent,
                                          interface_rate=test_scenario['port_bw'])).to_integral_value())
        if verbose is True:
            print "Percent from bw {0}% packet size {1} byte calculated pps {2} pps".format(link_percent,
                                                                                            actual_pkt_size,
                                                                                            stream_rate)

    # in fixed mode we care only about flow rate
    elif 'fixed' in flow['rate-mode']:
        if 'stream-rate' not in flow:
            print "{0}Error: \'{1}\' is mandatory field for test flow {2}" \
                  "".format(bcolors.FAIL, 'percent', bcolors.ENDC)
            return stream_rate
        stream_rate = long(flow['stream-rate'].replace(' ', '')[:-3])
    else:
        print "{0}Error: \'{1}\' is mandatory field for test flow {2}".format(bcolors.FAIL, 'port_bw', bcolors.ENDC)
        return stream_rate

    return stream_rate

def build_stream(test_plan=None, flow=None, flow_id=0, target_packet_size=0, rate=None, verbose=False):
    """

    :param verbose:
    :param rate:
    :param test_plan:
    :param flow:
    :param flow_id:
    :param target_packet_size:
    :return:
    """

    stream = {}
    if flow is None:
        return stream

    # if we do have packet size for respected flow we use it
    if 'packet-size' in flow:
        target_packet_size = flow['packet-size']

    packet_size = target_packet_size - 4  # we need 4 byte for checksum
    if 'ranges' in flow:
        cfg_range = flow['ranges'][0]
        ip_range = {'src': {'start': cfg_range['src-start'], 'end': cfg_range['src-end']},
                    'dst': {'start': cfg_range['dst-start'], 'end': cfg_range['dst-end']}}

        src = ip_range['src']
        dst = ip_range['dst']

        vm = [
            # src
            STLVmFlowVar(name="src", min_value=src['start'], max_value=src['end'], size=4, op="inc"),
            STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),

            # dst
            STLVmFlowVar(name="dst", min_value=dst['start'], max_value=dst['end'], size=4, op="inc"),
            STLVmWrFlowVar(fv_name="dst", pkt_offset="IP.dst"),

            # checksum
            STLVmFixIpv4(offset="IP")
        ]

        if 'vlan' in flow:
            pkt_base = Ether(src=flow['srcmac'], dst=flow['dstmac']) / \
                       Dot1Q(vlan=flow['vlan']) / \
                       IP() / \
                       UDP(dport=flow['srcport'], sport=flow['dstport'])
        else:
            pkt_base = Ether(src=flow['srcmac'], dst=flow['dstmac']) / \
                       IP() / \
                       UDP(dport=flow['srcport'], sport=flow['dstport'])

        pyld_size = packet_size - len(pkt_base)
        pkt_pyld = generate_payload(pyld_size)
        pad = pkt_pyld
        gen_packet = STLPktBuilder(pkt=pkt_base / pkt_pyld, vm=vm)
        frame = pkt_base
    else:
        if 'vlan' in flow:
            frame = Ether(src=flow['srcmac'], dst=flow['dstmac']) / \
                    Dot1Q(vlan=flow['vlan']) / \
                    IP(src=flow['srcip'], dst=flow['dstip']) / \
                    UDP(dport=flow['srcport'], sport=flow['dstport'])
        else:
            frame = Ether(src=flow['srcmac'], dst=flow['dstmac']) / \
                    IP(src=flow['srcip'], dst=flow['dstip']) / \
                    UDP(dport=flow['srcport'], sport=flow['dstport'])


        pad = max(0, packet_size - len(frame)) * 'x'
        gen_packet = STLPktBuilder(pkt=frame / pad)

    if rate is None or rate is 0:
        calculated_rate = calculate_rate(test_scenario=test_plan, flow=flow,
                                         packet_size=target_packet_size,
                                         verbose=verbose)
    else:
        calculated_rate = rate

    if verbose is True:
        print "Creating flow id {0}: calculated rate {1} payload " \
              "len {2} frame len {3} total size {4}".format(flow['id'],
                                                            calculated_rate,
                                                            len(pad),
                                                            len(frame) + 4,
                                                            len(pad) + len(frame))
    # print gen_packet.get_vm_data()
    # print "Calculated rate {0} pps".format(calculated_rate)
    if 'latency' in flow and flow['latency'] is True:
        stream = STLStream(name="{0} - flow {1}".format(test_plan['name'], flow_id),
                           packet=gen_packet,
                           mode=STLTXCont(pps=calculated_rate),
                           flow_stats=STLFlowLatencyStats(pg_id=flow["id"]))
    else:
        stream = STLStream(name="{0} - flow {1}".format(test_plan['name'], flow_id),
                           packet=gen_packet,
                           mode=STLTXCont(pps=calculated_rate),
                           flow_stats=STLFlowStats(pg_id=flow["id"]))

    stream_dict = {'stream': stream,
                   'stream-rate': calculated_rate,
                   'payload-size': len(pad),
                   'hdr-size': len(frame) + 4,
                   'packet-size': packet_size,
                   'flow_id': flow_id}

    return stream_dict


def create_flow_table():
    """

    :return:
    """
    flow_table = PrettyTable()
    flow_table.field_names = ["pps", "flow id", "rate - %/pps", "src mac", "dst mac",
                              "src ip", "dst ip", "src port", "dst port",
                              "vlan", "frame hdr size", "payload size",
                              "total size", "max pps"]

    flow_table.align["pps"] = "r"
    flow_table.align["rate - %/pps"] = "l"

    return flow_table


def create_result_table():
    """

    :return:
    """
    return PrettyTable(['run #', 'flow id', 'packet size', 'avg lost', 'flow pkt-tx', 'flow pkt-rx', 'status',
                        'egress port', 'ingres port', 'Port Tx (Mpps)', 'Port Rx (Mpps)', 'Port Tx (Gbps)',
                        'Port Rx (Gbps)', 'lat min', 'lat max', 'lat avg', 'jitter', 'agg pps'])


def create_excel_workbook(result_filename=None):
    """

    :param result_filename:
    :return:
    """
    workbook = xlsxwriter.Workbook(result_filename)
    worksheet = workbook.add_worksheet()

    # headings
    headings = ['flow id', 'packet size', 'avg lost', 'flow pkt-tx', 'flow pkt-rx', 'status',
                'egress port', 'ingres port', 'Port Tx (Mpps)', 'Port Rx (Mpps)', 'Port Tx (Gbps)',
                'Port Rx (Gbps)', 'lat min', 'lat max', 'lat avg', 'jitter']
    bold = workbook.add_format({'bold': 1})
    worksheet.write_row('A1', headings, bold)

    return workbook


def output_result_table(result_table):
    """

    :param result_table:
    :return:
    """
    # sort and print result
    print result_table.get_string(sort_key=operator.itemgetter(0, 1), sortby="run #")


def tester(frame_size=0, throttle=0, test_scenario=None, generic_stats_tlb=None, verbose=False):
    """

    :param frame_size: an optional in case client wish to run all flow with fixed size packet
                       otherwise packet size derived from each respected flow.

    :param test_scenario: a test scenario configuration that client wish to execute.
    :return:
    """
    stlclient = STLClient()
    if 'test-result' not in test_scenario:
        print "test-result mandatory field check configuration file."

    finish = False
    try:

        stlclient.connect()

        flow_table = copy.deepcopy(test_scenario['flows'])
        adaptive = test_scenario['adaptive']
        iteration = 1

        while finish is False and iteration <= test_scenario['max-iteration']:
            streams_list = []
            output_flow_table = create_flow_table()

            # build all flow
            for index, flow in enumerate(flow_table):

                # validate entire scenario
                if validate_scenario(flow=flow, test_plan=test_scenario) is False:
                    return

                # we set packet size for a flow.
                if 'packet-size' not in flow:
                    flow['packet-size'] = frame_size

                # for each flow we set a reference max pps for a given packet size.
                # we don't use this value it only for reference
                max_pps = long(Decimal(maxpps(packet_size=flow['packet-size'], percent=100,
                                              interface_rate=test_scenario['port_bw'])).to_integral_value())
                if 'max-pps' not in flow:
                    flow['max-pps'] = max_pps

                # build a stream
                stream = build_stream(test_plan=test_scenario, flow=flow, flow_id=index, verbose=verbose)
                if stream is None:
                    print "{0}Error: Failed create stream.{1}".format(bcolors.FAIL, bcolors.ENDC)

                # append each flow to output flow table we use it to print all flows
                append_flow(flow_table=output_flow_table, flow=flow,
                            flow_rate=stream['stream-rate'],
                            header_size=stream['hdr-size'],
                            payload_size=stream['payload-size'])

                # we pack everything to a dict
                # stream - is trex stream
                # rate - is an aggregate rate what we will run at T0 a stream
                # ingress_port - is port we will use to inject traffic
                # egress_port  - is egress port that will receive traffic
                stream_dict = {'stream': stream['stream'],
                               'rate': stream['stream-rate'],
                               'egress_port': flow['egress_port'],
                               'ingress_port': flow['ingress_port'],
                               'isauto': ('auto' in flow['rate-mode'])}

                streams_list.append(stream_dict)

            print "{0}Flow table: {1}".format(bcolors.OKGREEN, bcolors.ENDC)
            print output_flow_table

            # 'packet_size': packet_size,
            streams = {'streams': streams_list,
                       'frame_size': frame_size,
                       'throttle': throttle}

            finish = run_streams(stlclient,
                                 stream_dict=streams,
                                 test_scenario=test_scenario,
                                 flow_table=flow_table,
                                 generic_stats_tlb=generic_stats_tlb,
                                 iteration=iteration,
                                 verbose=verbose)

            # if test is not adaptive and we failed we break
            if finish is False and adaptive is False:
                return generic_stats_tlb

            sys.stdout.write("\r")
            sys.stdout.flush()
            iteration += 1

    except STLError as e:
        print(e)

    finally:
        stlclient.disconnect()

    return generic_stats_tlb


def print_max_pps(pkt_sizes=None, percents=None, pps_output_tlb=None, doprint=True):
    """
    Prints max pps for a given packet size and test to console

    :param pps_output_tlb:
    :param doprint:
    :param percents:
    :param pkt_sizes:
    :return:
    """
    if pkt_sizes is None:
        pkt_sizes = [64]

    if percents is None:
        percents = [100]

    if pps_output_tlb is None:
        pps_output_tlb = PrettyTable(["Packet size", "Line rate 10Gbe", "Line rate 40Gbe", "Percentage"])

    if len(pkt_sizes) is not len(percents):
        return

    for idx, pkt_size in enumerate(pkt_sizes):
        gbe10_maxpps_indec = Decimal(maxpps(packet_size=pkt_size, percent=percents[idx], interface_rate=1000))
        gbe40_maxpps_indec = Decimal(maxpps(packet_size=pkt_size, percent=percents[idx], interface_rate=4000))
        gbe10_maxpps = round(gbe10_maxpps_indec, 0)
        gbe40_maxpps = round(gbe40_maxpps_indec, 0)

        pps_output_tlb.add_row(
            [pkt_size, "{:,} pps".format(gbe10_maxpps), "{:,} pps".format(gbe40_maxpps), percents[idx]])

    if doprint is True:
        print(pps_output_tlb)


def fixed_packet_size_test(test_scenario=None, generic_stats_tlb=None, console_output_tlb=None, verbose=False):
    """
    Fixed packet size iteration test handle a test scenario where we have list of packet size and respected
    percentage from reference bandwidth.

    :param test_scenario: configuration dict for entire scenario.
    :param generic_stats_tlb: table used for test result stats report
    :param console_output_tlb: table for flow console output
    :param verbose
    :return:
    """

    try:
        if 'packet-size' not in test_scenario:
            print "{0}Error: \'{1}\' is mandatory field for fixed size packet iteration " \
                  "test. {2}".format(bcolors.FAIL, 'packet-size', bcolors.ENDC)
            return False

        for pkt_size in test_scenario['packet-size']:

            # print max pps for a given packet size
            packet_sizes = [pkt_size['size']]
            print_max_pps(pkt_sizes=packet_sizes, percents=[100])

            print "{0}Executing test \"{1}\".{2}".format(bcolors.OKGREEN, test_scenario['name'], bcolors.ENDC)

            # run test scenario
            # TODO packet pkt and throttle
            throttle = 0
            if 'throttle' in pkt_size:
                throttle = pkt_size['throttle']
            generic_stats_tlb = tester(frame_size=pkt_size['size'],
                                       throttle=throttle,
                                       test_scenario=test_scenario,
                                       generic_stats_tlb=generic_stats_tlb,
                                       verbose=verbose)
            # populate console report table
            console_report(console_output_tlb=console_output_tlb, generic_stats_tlb=generic_stats_tlb)
    except KeyError as e:
        print "{0} Invalid key. Check configuration file. {1}".format(bcolors.FAIL, bcolors.ENDC)
        print "".format(e)
    except TypeError as e:
        print "{0} Invalid type. Check configuration file. {1}".format(bcolors.FAIL, bcolors.ENDC)
        print "".format(e)

    return True


def imix_iteration_test(test_scenario=None, generic_stats_tlb=None, console_output_tlb=None, verbose=False):
    """
    IMIX iteration test handle test case where we have set ot flow with variable packet size each
    and percentage from a reference bandwidth.

    The percentage will be used to calcualte target pps values for a flow.

    Example:
       port_bw:  1000                    # port bandwidth
       ....
          - flow:   "128-byte-flow"
            decription: "single flow 128 byte 6% percent"
            id:     1
            packet-size: 128
            description: "voice"
            srcmac: "3C:FD:FE:B5:27:88"
            dstmac: "00:50:56:A5:49:9A"
            srcip:  1.1.1.1
            dstip:  2.1.1.2
            srcport: 1025
            dstport: 12
            vlan:   653
            egress_port: [0]               # egress port id or list of ports [0, 1]
            ingress_port: [0]              # ingress port id or list of ports [0, 1]
            rate-mode: auto                # support keyword auto or fixed. auto indicates that we calculate
                                           #from reference bandwidth a percentage

            percent: 6                     # 50 percent in one direction relevant only if rate-mode auto
            latency: False
            throttle: 1                    # indicate for how much we reduce rate for adaptive mode.

    :param test_scenario: configuration dict for entire scenario.
    :param generic_stats_tlb: table used for test result stats report
    :param console_output_tlb: table for flow console output
    :param verbose=False
    :return:
    """

    if verbose is True:
        print "{0} Executing test \"{1}\"" \
              "all by supplying argument all.{2}".format(bcolors.OKGREEN, test_scenario['name'], bcolors.ENDC)

    pps_output_tlb = PrettyTable(["Packet size", "Line rate 10Gbe", "Line rate 40Gbe", "Percentage"])

    try:
        for flow in test_scenario['flows']:
            if 'packet-size' not in flow:
                print "{0}Error in test {1}: \'{2}\' is mandatory field for this " \
                      "type of a test. {3}".format(bcolors.FAIL, test_scenario['name'], 'packet-size', bcolors.ENDC)
                return
            print flow['stream-rate']

            if 'percent' not in flow and 'stream-rate' not in flow:
                print "{0}Error in test {1}: \'{2}\' is mandatory field for this type of " \
                      "a test. {3}".format(bcolors.FAIL, test_scenario['name'], 'percent or stream-rate', bcolors.ENDC)
                return

            packet_sizes = [flow['packet-size']]
            if 'percent' in flow:
                distribution = [flow['percent']]
            else:
                distribution = [100]

            print_max_pps(pkt_sizes=packet_sizes,
                          percents=distribution,
                          pps_output_tlb=pps_output_tlb, doprint=False)
        # output pps table
        print pps_output_tlb

        generic_stats_tlb = tester(test_scenario=test_scenario,
                                   generic_stats_tlb=generic_stats_tlb,
                                   verbose=verbose)
        if generic_stats_tlb is False:
            print "{0}Failed execute a test scenario: {1}: {2}".format(bcolors.FAIL,
                                                                       test_scenario['name'],
                                                                       bcolors.ENDC)
            return False
        else:
            # generate console report
            console_report(console_output_tlb=console_output_tlb, generic_stats_tlb=generic_stats_tlb)

    except KeyError as e:
        print "{0} Invalid key. Check configuration file. {1}".format(bcolors.FAIL, bcolors.ENDC)
        print "".format(e)
    except TypeError as e:
        print "{0} Invalid type. Check configuration file. {1}".format(bcolors.FAIL, bcolors.ENDC)
        print "".format(e)


def read_test_scenarios(config=None):
    """
    Read configuration yaml files and populate and return a dict.

    :param config:
    :return: returns populated dict with scenarios.
             each dict contains scenario name as key,  string that represents a path for environment
             and scenario itself as key value pair.
    """
    test_scenarios = {[]}
    if 'tester' not in config:
        return test_scenarios

    try:
        for test_description in config['tester']:
            test_name = test_description['name']
            if test_name is None or len(test_name) is 0:
                continue
            if 'test-environment' in test_description:
                test_environment = test_description['test-environment']
            else:
                test_environment = None

            logging.info("Reading {0}".format(test_description['test-scenario']))
            scenario_config = yaml.load(open(test_description['test-scenario']))
            if scenario_config is None or 'scenario' not in scenario_config:
                print "{0}Error: each test plan must have at least one test. {1}".format(bcolors.FAIL, bcolors.ENDC)
                return test_scenarios

            test_construct = {'test_environment': test_environment, 'scenario': scenario_config}
            test_scenarios[test_name] = test_construct

    except IOError as e:
        print "{0}Error opening file {1} {2}".format(bcolors.FAIL,
                                                     test_description['test-scenario'],
                                                     bcolors.ENDC)
        print e.message
    except yaml.parser.ParserError as e:
        print "Error opening file syntax error in yaml file.".format(bcolors.FAIL,
                                                                     test_description['test-scenario'],
                                                                     bcolors.ENDC)
        print e.message

    return test_scenarios


def execute_scenario(execute=None, test_scenarios=None, test_environment=None, verbose=False):
    """

    :param execute:
    :param test_scenarios:
    :param test_environment:
    :param verbose
    :return:
    """

    if test_environment is not None and len(test_environment) > 0:
        setup_environment(test_environment)

    try:
        scenarios = test_scenarios['scenario']
        for test_plan in scenarios:
            logging.info("Executing test scenario {0}".format(test_plan['name']))
            generic_stats_tlb = []
            console_output_tlb = create_result_table()

            if execute in test_plan['name'] or 'all' in execute:
                if 'flows' not in test_plan:
                    continue
            if 'test-type' in test_plan and 'packet-iteration' in test_plan['test-type']:
                fixed_packet_size_test(test_scenario=test_plan,
                                       generic_stats_tlb=generic_stats_tlb,
                                       console_output_tlb=console_output_tlb,
                                       verbose=verbose)

            if 'test-type' in test_plan and 'imix-iteration' in test_plan['test-type']:
                imix_iteration_test(test_scenario=test_plan,
                                    generic_stats_tlb=generic_stats_tlb,
                                    console_output_tlb=console_output_tlb,
                                    verbose=verbose)

            #output result to console and save to a file.
            if len(generic_stats_tlb) > 0:
                sys.stdout.write("\r")
                sys.stdout.flush()
                print "{0}Stream result: {1}".format(bcolors.OKGREEN, bcolors.ENDC)
                logging.info("{0}Stream result: {1}".format(bcolors.OKGREEN, bcolors.ENDC))
                output_result_table(result_table=console_output_tlb)
                if 'test-result' in test_plan and 'cvs' in test_plan['test-result-format']:
                    file_name = test_plan['test-result'] + ".cvs"
                    save_as_cvs_report(test_result=generic_stats_tlb,
                                       result_filename=file_name,
                                       passed_only=False,
                                       stats_filter=test_plan['report-formater'])
                if 'test-result' in test_plan and 'xlsx' in test_plan['test-result-format']:
                    file_name = test_plan['test-result'] + ".xlsx"
                    save_as_excel_report(test_result=generic_stats_tlb,
                                         result_filename=file_name,
                                         passed_only=True)
    except KeyError as e:
        print "key error".format(e)

    # stop entire environment only if we bootstraped anything
    if test_environment is not None and len(test_environment) > 0:
        teardown_environment(test_environment)


def main(execute=None, verbose=True, config_file=None):
    """
    Main entry for ens tester.

    :param execute:
    :param verbose:
    :param config_file:
    :return:
    """
    if verbose is True:
        print "Reading default configuration file {0}".format("tester-config.yaml")

    if config_file is None or len(config_file) is 0:
        logging.info("Reading default configuration file {0}".format("tester-config.yaml"))
        config = yaml.load(open("tester-config.yaml"))
    else:
        logging.info("Reading default configuration file {0}".format(config_file))
        config = yaml.load(config_file)

    test_scenarios = read_test_scenarios(config)
    for key, value in test_scenarios.iteritems():
        test_environment=value['test_environment']
        test_scenarios=value['scenario']
        execute_scenario(execute=execute, test_scenarios=test_scenarios, test_environment=test_environment)


if __name__ == "__main__":
    """
    """
    if len(sys.argv) < 2:
        print "{0}Error: Please indicate test name to run for example \"tc-1.1\" or run " \
              "all by supplying argument all.{1}".format(bcolors.FAIL, bcolors.ENDC)

        sys.exit(10)

    main(execute=sys.argv[1], verbose=True)
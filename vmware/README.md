## trex-automation
trex automation tools


trex automation tools that allows create generic test template and scenario , parepare environment and create custom
script that you can run before test execution.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Project has following python dependancies

```
PrettyTable
XlsxWriter
YAML
Paramiko
Trex API
```

### Installing


```
$ sudo apt-get install python-yaml

or

pip install pyyaml

or

$ sudo yum install python-yaml

```

We need install XlsxWriter, PrettyTable and paramiko python packages

```
$ sudo pip install XlsxWriter
$ sudo pip install prettyrable
$ sudo pip install paramiko

```


trex instaled in /home/trex/v2.36/  and we are going to clone repo inside automation/trex_control_plane/stl/

```
cd /home/trex/v2.36/
cd automation/trex_control_plane/stl/
git clone https://github.com/spyroot/trex-automation
```

It should look this

```
$ cd  /home/vmware/v2.36/automation/trex_control_plane/stl
$ ls
console  examples  services  trex-automation  trex_stl_lib
```

```
$ sudo su -
echo "TREX_PATH=/home/vmware/v2.36/automation/trex_control_plane/stl"  /root/.bashrc
echo "export TREX_PATH" > /root/.bashrc

$ cd /home/vmware/v2.36/automation/trex_control_plane/stl/examples
```

We need that step in order trex-automation find python trex libs

```
$ cd /home/vmware/v2.36/automation/trex_control_plane/stl/examples
# cp stl_path.py /home/vmware/v2.36/automation/trex_control_plane/stl/trex-automation/vmware
```


```
```


## Usage

Tools provide you option describe each test as the scenario.
Each scenario described in separate yaml.

For example, we first create a tester-config.yaml that consists a list of test scenarios.

### Example

```

tester:
- test:     1
name:     "test 5.1.1"
test-scenario:   "scenarios/telia/5.1.1/test.5.1.1.yaml"
test-environment: "scenarios/environment-l2core.yaml"         #      test-environment is optional
```


Here we have to main entry first is path to a test scenarion and path to yaml file that describes
automation workflow.  It allows tools prepare a test environment for example if we want deploy specific DPDK L3FWD VM on target
ESXI host, preppare configuration or use custom start /stop scripts. 

In test-scenario section wee need point to a valid yaml file that describe test itself.  We start test scenario 
execute a test after test invironment prepared. 

Example of enviroment file.

Please note it YAML file so make sure you use space separation only

```
target-hosts:
- host:    1						# ID here must be a unique
name:   "esxi-host1"				# just user friendly name
host:   "192.168.1.1"				# We use IP address to ssh to a host
password:   "rootpassword"		# here we use root password. (it ESXi host)	    
username:   "root"
port:   22						# we need that in case we use custom port
execute-cli-list:					# here we need list all CLI command we want to execute in seq.
# here we have list command that we want to executed before we start our test test.
# in this case we allocate lcore per each vNIC before test starts.
- cmd: "nsxdp-cli ens port migrate -p 2 -l 1 -d 0;nsxdp-cli ens port migrate -p 2 -l 1 -d 1"
- cmd: "nsxdp-cli ens port migrate -p 3 -l 1 -d 0;nsxdp-cli ens port migrate -p 3 -l 1 -d 1"
- cmd: "nsxdp-cli ens port migrate -p 4 -l 2 -d 0;nsxdp-cli ens port migrate -p 4 -l 2 -d 1"
- cmd: "nsxdp-cli ens port migrate -p 5 -l 2 -d 0;nsxdp-cli ens port migrate -p 5 -l 2 -d 1"

```

### Define VM or baremental that is our device under a test.

Here we define element under a test.  For example if we have DPDK enabled VM we define
Virtual host with DPDK instlaled and start and stop script.  in this case we connect to
a host run a command to start DPDK l3fwd as root via sudo. forwarder-stop and forwarder-start
indicate script we need use to start the environment and stop the environment

```
dpkd-hosts:
- dpdk:     1
name:   "dpdk-vm1"				# just friend name
host:   "192.168.1.1"				# DNS FQDN or IP.
password:   "my_password"
username:   "dpdk"				# make sure host has access to target system
port:   22						# we use this to ssh to a host
#  here we define a start up script and script we use to stop a forwarder.
app-stop: "echo 'root_password!' | sudo -S kill $(ps aux | grep 'l3fwd' | awk '{print $2}')"
app-start: "echo 'root_password!' | sudo -S nohup /home/dpdk/startL3fwd-app.sh >> /tmp/l3fwd-app.log 2>>/tmp/l3fwd-app.log"
```


### Test scenario.


Each test scenario consists two main blocks the general section that relevant for an entire test scenario.
In this section, we define where we want to save test result, a name of the test scenario, number of iteration for the test.

The second block consists actual test flow that tester will inject.

The test scenario supports different flavors.   For example, we can define a test that will evaluate a pps performance based on pre-defined list packet size.   We can also indicate this test as an adaptive mode where tools will try to reduce a rate in case target element can't perform a target rate/pps.   In this mode, tools will reduce a rate and re-try to execute a flow.  It will stop testing given size when test passed a target pps rate, or it reaches the max number of iteration.

Mix-Iteration define maximum number of times we execute test in adaptive mode.


```

scenario:
- test:     1
name:     "vm-to-vm-2lcore"
test-result:   "/home/trex/Results/vm-to-vm-2lcore-70byte"
test-result-format: ["xlsx", "csv"]
report-formater:  ['flow_id', 'tx_pps', 'rx_pps', 'flow_status', 'packet_size']
max-iteration: 50
max-duration:  60
acceptable-loss: 0.001
acceptable-rx-overflow: 0.001
adaptive: False                   # indicate if we fail a test we drop a rate to next pps
port_bw:  1000                    # port bandwidth
test-type: "imix-iteration"       # indicate we want to do packet iteration. each flow will be constructed with each respected packet size
flows:
- flow:   "70-byte-flow-l-r"
ranges:
- range: "two"
src-start: "1.1.1.1"
src-end: "1.1.1.10"
dst-start: "3.1.1.2"
dst-end: "3.1.1.10"
id:     1
description: "tcp ack"
packet-size: 70
srcmac: "3C:FD:FE:B5:27:88"
dstmac: "00:50:56:A5:49:9A"     # vm 1 eth 2 port
srcport: 1025
dstport: 12
vlan:   653
egress_port: [0]                # egress port id or list of ports [0, 1]
ingress_port: [0]               # ingress port id or list of ports [0, 1]
rate-mode: fixed                # support keyword auto or fixed. auto indicates that we calculate from reference bandwidth a percentage
stream-rate: "600000pps"        # stream rate can either pps value or port percentage 10% or 1pps
latency: False

- flow:   "70-byte-flow-l-r"
ranges:
- range: "two"
src-start: "3.1.1.1"
src-end: "3.1.1.10"
dst-start: "1.1.1.2"
dst-end: "1.1.1.10"
id:     2
description: "tcp ack"
packet-size: 70
srcmac: "3C:FD:FE:B5:27:88"
dstmac: "00:50:56:A5:92:51"     #VM - 2 mac address eth3
srcport: 1025
dstport: 12
vlan:   653
egress_port: [0]                # egress port id or list of ports [0, 1]
ingress_port: [0]               # ingress port id or list of ports [0, 1]
rate-mode: fixed                # support keyword auto or fixed. auto indicates that we calculate from reference bandwidth a percentage
stream-rate: "600000pps"        # stream rate can either pps value or port percentage 10% or 1pps
latency: False

- flow:   "70-byte-flow-l-r"
ranges:
- range: "two"
src-start: "2.1.1.1"
src-end: "2.1.1.10"
dst-start: "4.1.1.2"
dst-end: "4.1.1.10"
id:     3
description: "tcp ack"
packet-size: 70
srcmac: "3C:FD:FE:B5:27:88"
dstmac: "00:50:56:A5:0A:3A"   # vm 1 eth 2 port
srcport: 1025
dstport: 12
vlan:   653
egress_port: [0]                # egress port id or list of ports [0, 1]
ingress_port: [0]               # ingress port id or list of ports [0, 1]
rate-mode: fixed                # support keyword auto or fixed. auto indicates that we calculate from reference bandwidth a percentage
stream-rate: "600000pps"        # stream rate can either pps value or port percentage 10% or 1pps
latency: False
```


### Example of flow definition for latency messurment.

Here we define additional flow that fixed 1000pps rate and we indicate that we want
to messure a latency.  The statistic for this flow will also include latency stats.

```
- flow:   "70-byte-flow-l-r"
ranges:
- range: "two"
src-start: "1.1.1.1"				# based on default routing table for L3fwd sample app
src-end: "1.1.1.10"
dst-start: "3.1.1.2"
dst-end: "3.1.1.10"
id:     5
description: "latency flow"
packet-size: 70
srcmac: "3C:FD:FE:B5:27:88"
dstmac: "00:50:56:A5:49:9A"     # vm 1 eth 2 port
srcport: 1025
dstport: 12
vlan:   653						# vlan is optional. 
egress_port: [0]                # egress port id or list of ports [0, 1]
ingress_port: [0]               # ingress port id or list of ports [0, 1]
rate-mode: "fixed"              # support keyword auto or fixed.
# auto indicates that we calculate from reference bandwidth a percentage
stream-rate: "1000pps"          # stream rate can either pps value or port percentage 10% or 1pps
latency: True
```

## Deployment

Add additional notes about how to deploy this on a live system

## Built With

## Contributing

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 

## Authors

* **Mustafa Baymov ** - *Initial work* 

See also the list of [contributors](https://github.com/your/project/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



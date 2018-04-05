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

For example, we create a tester-config.yaml that consists a list of tests.

### Example

```

tester:
    - test:     1
      name:     "test 5.1.1"
      test-scenario:   "scenarios/telia/5.1.1/test.5.1.1.yaml"
      test-environment: "scenarios/environment-l2core.yaml"         #      test-environment is optional
```


Here we have to main entry first is path to a test scenarion and path to yaml file that describes
automation workflow.  Basically if we need prepare test environment we describe list of host
that we execute automation workflow.

### Break down into end to end tests

Explain what these tests test and why

```
Give an example
```

### And coding style tests

Explain what these tests test and why

```
Give an example
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



## trex-automation
trex automation tools


trex automation tools that allows create generic test template and scenario , parepare environment and create custom
script that you can run before test execution.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

Project has following python dependancies

```
prettytable
xlsxwriter
yaml
Trex API
```

### Installing



```
You need copy files where your trex automation resides
For example:

$ sudo apt-get install python-yaml

or

pip install pyyaml

or

$ sudo yum install python-yaml

trex instaled in /home/trex/v2.36/
We create dir

mkdir automation/trex_control_plane/stl/bin

cd to folder where cloned trex automation
cp ens_tester.py dpdk_environment.py automation/trex_control_plane/stl/bin

create a file stl_path.py and indicate trex python resides

import sys, os

# FIXME to the right path for trex_stl_lib
cur_dir = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(cur_dir, os.pardir))

STL_PROFILES_PATH = os.path.join(os.pardir, os.pardir, os.pardir, os.pardir, 'stl')

```

And repeat

```
until finished
```

End with an example of getting some data out of the system or using it for a little demo

## Running the tests

Explain how to run the automated tests for this system

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



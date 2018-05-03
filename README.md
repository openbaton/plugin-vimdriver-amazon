 <img src="https://raw.githubusercontent.com/openbaton/openbaton.github.io/master/images/openBaton.png" width="250"/>
  
  Copyright © 2015-2017 [Open Baton](http://openbaton.org). 
  Licensed under [Apache v2 License](http://www.apache.org/licenses/LICENSE-2.0).
  
[![Build Status](https://travis-ci.org/openbaton/plugin-vimdriver-amazon.svg?branch=master)](https://travis-ci.org/openbaton/plugin-vimdriver-amazon)

# Open Baton Amazon EC2 Driver
  
  This project **amazon-plugin** contains an implementation of a driver for integrating Open Baton with Amazon EC2 service. 
  This plugin uses the plugin-sdk allowing the NFVO to interoperate with this plugin using AMQP. 
  This plugin uses Amazon Java SDK as implementation of the Amazon Cloud API. 
  
## How to install Amazon EC2 driver
  You can clone the source code and build the plugin with gradle. After that take the compiled jar and copy it to the folder where the NFVO searches for the plugins.
  
## How to start the Amazon driver standalone mode

If you have placed the plugin as it was mentioned earlier, then NFVO will automatically start it with the right parameters. The plugin however is by itself an application which can be started remotely by using CLI. For this, you will need to type this into console. 

```bash
$ java -jar path-to-plugin.jar amazon [rabbitmq-ip] [rabbitmq-port] [n-of-consumers] [user] [password]
```

* **amazon** represents the unique name given to this vim driver 
* **rabbitmq-ip** is the ip of the host where the rabbitmq server is installed and running
* **rabbitmq-port** is the port on which the rabbitmq accepts the messages(it is usually 5672 by default) 
* **number-of-consumers** specifies the number of actors that will accept the requests

## How to use the Amazon EC2 driver

* Create a security group or use default one. In both cases make sure that the instances can communicate through the ports that you need for both messaging with broker (rabbitmq) and your specific services. Security groups should have access to internet.
* Create a VPC or use a default one. Do not forget to give the name to the vpc. It is a requirement for aws plugin This will be the tenant in the current VIM information. 
* Disable quota-check the NFVO properties
* Makes sure that all networks that you already have on VPC have names
* Make sure that the main route table on the VPC is connected to non-NAT gateway if you want to SSH into the instances after deployment
* Get your access key and access secret key from your aws account. It will be username and password in your VIM information.
* Locate the region you want to work in and use the name to of the region without the letter in the end, for example us-east-2
* After you have all this data either create the form as a json data or fill out the form in the dashboard to upload your vim information to NFVO.
* Due to the high number of images in AWS it is not feasible to list all of the in dashboard of the openbaton, you can use any images found on AWS, but only those that in properties would be listed in NFVO.
* All the instances currently get the public ip assigned to them in order to provide the internet functionality. For the instances that have more than 1 interface, elastic ip will be used, remember, 
that by default the user has generally only 5 elastic ips available. 

```properties
type = amazon
external-properties-file = /etc/openbaton/plugin/amazon/driver.properties
image-key-word = ami-10547475,ami-8a7859ef,ami-f990b69c,ami-43391926
launchTimeout = 128
```
image-key-word property provides an ability to list images that you want from the openbaton, it is recommended to paste the ids of the image which you can get from AWS itself, so that you can 
see the images from the openbaton dashboard, however, you can use any image listed on AWS, the check on whether the image is present will be done during launch attempt by the plugin itself

launchTimeout property define how long the plugin should wait for the instance to get in status "running" before assuming that the instance was not launched for some reason

A step-by-step tutorial on how to make those changes is available [here for the dashboard](docs/how-to-ec2-dashboard.md) and [here for the CLI](docs/how-to-ec2-cli.md)

**Disclaimer:** Please be careful while writing your NSD or creating packages, pay attention to the types of instances that you are using, plugin does not keep
track of the charges that may apply.
* If you want to use generic-vnfm and EMS that it is coupled with be aware that rabbitmq-host should be reachable from AWS instances. One of the options in this case is to manually create an instance inside AWS amd install rabbitmq there. The rabbitmq may be reached with instances public DNS after it by all the components.

# What is Open Baton?

Open Baton is an open source project providing a comprehensive implementation of the ETSI Management and Orchestration (MANO) specification and the TOSCA Standard.

Open Baton provides multiple mechanisms for interoperating with different VNFM vendor solutions. It has a modular architecture which can be easily extended for supporting additional use cases. 

It integrates with OpenStack as standard de-facto VIM implementation, and provides a driver mechanism for supporting additional VIM types (including Amazon EC2, and Docker). It supports Network Service management either using the provided Generic VNFM and Juju VNFM, or integrating additional specific VNFMs. It provides several mechanisms (REST or PUB/SUB) for interoperating with external VNFMs. 

It can be combined with additional components (Monitoring, Fault Management, Autoscaling, and Network Slicing Engine) for building a unique MANO comprehensive solution.

## Source Code and documentation

The Source Code of the other Open Baton projects can be found [here][openbaton-github] and the documentation can be found [here][openbaton-doc]

## News and Website

Check the [Open Baton Website][website]

Follow us on Twitter @[openbaton][openbaton]

## Licensing and distribution
Copyright © [2015-2017] Open Baton project

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Support
The Open Baton project provides community support through the Open Baton Public Mailing List and through StackOverflow using the tags openbaton.

## Supported by
  <img src="https://raw.githubusercontent.com/openbaton/openbaton.github.io/master/images/fokus.png" width="250"/><img src="https://raw.githubusercontent.com/openbaton/openbaton.github.io/master/images/tu.png" width="150"/>

[plugin-sdk-link]: https://github.com/openbaton/plugin-sdk
[nfvo-link]: https://github.com/openbaton/NFVO
[openbaton-github]: https://github.com/openbaton
[generic-link]:https://github.com/openbaton/generic-vnfm
[get-openbaton-org]:http://get.openbaton.org/plugins/stable/
[client-link]: https://github.com/openbaton/openbaton-client
[spring.io]:https://spring.io/
[NFV MANO]:http://docbox.etsi.org/ISG/NFV/Open/Published/gs_NFV-MAN001v010101p%20-%20Management%20and%20Orchestration.pdf
[openbaton]:http://twitter.com/openbaton
[website]:http://openbaton.github.io/
[get-openbaton-org-liberty]:http://get.openbaton.org/plugins/1.0.2-liberty-nighly/
[openbaton-doc]:http://openbaton.github.io/documentation/


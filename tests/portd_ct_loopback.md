#Loopback Interface CT Test Cases for dameon
<!-- TOC depth:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Sub-Interface Test Cases](#sub-interface-test-cases)
	- [Verify sub-interface Configurations](#verify-sub-interface-configurations)
		- [Objective](#objective)
		- [Requirements](#requirements)
	- [Setup](#setup)
		- [Topology Diagram](#topology-diagram)
		- [Test Setup](#test-setup)
	- [Test case 1.01 : Creat loopback interface with no shut down ](#test-case-101-Creat-loopback-interface- with-no-shutdown)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.02 : verify loopback interface created in kernel namespace ](#test-case-102- verify-loopback-interface-created-in-kernel-namespace)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.03 : assign ip address ](#test-case-103-assign-ipv4-configuration)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.04 : verify ip assigned to loopback interface ](#test-case-105-verify-ip-assigned -loopback-interface)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.05 : check ip get pingged](#test-case-106-check-ip-get-pinnged)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.06 : unassigned the ip address ](#test-case-107-unassigned-ip-address)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.07 : check ip get pinnged ](#test-case-109-check-ip-get-pinnged)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.08 : delet Loopback interface ](#test-case-110-delet-loopback-interfaces)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.09 : verify loopbackinterface removed in kernel name space ](#test-case-111-verify-loopback-interface-removed-from-kernel-name-space)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
<!-- /TOC -->

##  Verify sub-interface Configurations
### Objective
To create sub interface entry in port table and interface table
### Requirements
The requirements for this test case are:
 - Docker version 1.7 or above.
 - Accton AS5712 switch docker instance.

## Setup
### Topology Diagram
              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

### Test Setup
AS5712 switch instance.

## Test case 1.01 : creat and verify the loopback interface
Creat a Loopback interface and give no shutdown
### Description
Verify whether Loopback interface entry is created in kernel namespace.
### Test Result Criteria
#### Test Pass Criteria
Loopback Interface entry is created in kernel namespace
#### Test Fail Criteria
loopback Interface entry is not created in kernel name space

## Test case 1.02 : Assign IPv4 to sub interface
### Description
Verify whether ipv4 is assigned to Loopback-interface.
### Test Result Criteria
#### Test Pass Criteria
IPv4 is assigned to Loopback interface.
#### Test Fail Criteria
IPv4 is not assigned to Loopbac interface.

## Test case 1.04 :ping to assigned Ip from switch
### Description
Verify wether ping is success from switch console.
### Test Result Criteria
#### Test Pass Criteria
ping success.
#### Test Fail Criteria
ping failed .
### Test case 1.05 :Deconfigure IP
### Description
check the ip filed in kernel name space.
### Test Result Criteria
#### Test Pass Criteria
ip is not present.
#### Test Fail Criteria
Ip is present.
## Test case 1.06 :Ping to assigned IP from switch
### Description
Verify wether ping is success from switch console.
### Test Result Criteria
#### Test Pass Criteria
ping failed.
#### Test Fail Criteria
ping is success.

## Test case 1.07 :Delet Loopback Interface
### Description
delet Loopback interface and verify whether present in kernel name space
### Test Result Criteria
#### Test Pass Criteria
Loopback interface deleted.
#### Test Fail Criteria
Loopback interface still present.

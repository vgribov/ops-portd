# Sub-Interface CT Test Cases for dameon
<!-- TOC depth:6 withLinks:1 updateOnSave:1 orderedList:0 -->


- [Sub-Interface Test Cases](#sub-interface-test-cases)
	- [Verify sub-interface Configurations](#verify-sub-interface-configurations)
		- [Objective](#objective)
		- [Requirements](#requirements)
	- [Setup](#setup)
		- [Topology Diagram](#topology-diagram)
		- [Test Setup](#test-setup)
	- [Test case 1.01 : Creat subinterface and verify sub interface created in kernel name space ](#test-case-101-Creat-subinterface-and-verify-sub-nterface-created-in-kernel-name-space)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.02 : assign ip address ](#test-case-102-assign-ipv4-configuration)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.03 : Assign dot1Q encapsulation ](#test-case-103-Assign-dot1Q-encapsulation)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.04 : verify ip assigned to subinterface ](#test-case-104-verify-ip-assigned -subinterface)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.05 : check ip get pingged](#test-case-105-check-ip-get-pinnged)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.06 : unassigned the ip address ](#test-case-106-unassigned-ip-address)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.07 : check ip get pinnged ](#test-case-107-check-ip-get-pinnged)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
    - [Test case 1.08 : sub-interface marked down when unconfiguring dot1q encapsulation ](#test-case-108-sub-interface-marked-down-when-unconfiguring-dot1q-encapsulation)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
    - [Test case 1.09 : Ip address removed from asic when unconfiguring dot1q encapsulation ](#test-case-109-Ip-address-removed-from-asic-when-unconfiguring-dot1q-encapsulation)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.10 : Restartability of portd ](#test-case-110-Restartability-of-portd)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.11 : verifying configuration afrer system restart ](#test-case-111-verifying- configuration-afrer-system-restart)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
    - [Test case 1.12 : veryfy subinterface link state when parent interface link state goes down](#test-case-113\2-veryfy-subinterface-link-state-when-parent-interface-link-state-goes-down)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.13 : veryfy subinterface link state when parent interface no shutdown from shut down ](#test-case-113-veryfy-subinterface-link-state-when-parent-interface-no-hutdown-from-shut down)
		- [Description](#description)
		- [Test Result Criteria](#test-result-criteria)
			- [Test Pass Criteria](#test-pass-criteria)
			- [Test Fail Criteria](#test-fail-criteria)
	- [Test case 1.15 : delete subinterface and verify subinterface removed in kernel name space ](#test-case-115-delete-sub-interface-and-verify subinterface-removed-from-kernel-name-space)
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

## Test case 1.01 : Creat and Verify subinterface
Creat a subinterface and give no shutdown.
### Description
Verify whether sub interface entry is created in kernel namespace.
### Test Result Criteria
#### Test Pass Criteria
Sub Interface entry is created in kernel namespace .
#### Test Fail Criteria
Sub Interface entry is not created in kernel name space .

## Test case 1.02 : Assign IPv4 to sub interface
### Description
Verify whether ipv4 is assigned to sub-interface.
### Test Result Criteria
#### Test Pass Criteria
IPv4 is assigned to sub-interface.
#### Test Fail Criteria
IPv4 is not assigned to sub-interface.

## Test case 1.03 : Assign Dot1Q encapsulation
### Description
Whether encapsulation is set to sub-interface.
### Test Result Criteria
#### Test Pass Criteria
Dot 1Q encapsulation assigned .
#### Test Fail Criteria
Dot 1Q encapsulation not assigned .

## Test case 1.04 :Verify IP assigned to subinterface
### Description
Verify wether IP assigned to subinterface .
### Test Result Criteria
#### Test Pass Criteria
IP assigned to subinterface .
#### Test Fail Criteria
IP not assigned to sub interfce .

## Test case 1.05 :Ping to assigned IP from switch
### Description
Verify wether ping is success from switch console.
### Test Result Criteria
#### Test Pass Criteria
Ping success .
#### Test Fail Criteria
Ping failed .

### Test case 1.06 :Deconfigure IP
### Description
Check the IP filed in kernel name space.
### Test Result Criteria
#### Test Pass Criteria
Ip is not present .
#### Test Fail Criteria
IP still present .

## Test case 1.07 :Ping to assigned IP from switch
### Description
Verify wether ping is success from switch console.
### Test Result Criteria
#### Test Pass Criteria
Ping failed .
#### Test Fail Criteria
Ping is success .

## Test case 1.08 :Sub-interface goes down when unconfiguring dot1q encapsulation
### Description
Verify subinterafce state after deconfiguring dot1q encapsulation.
### Test Result Criteria
#### Test Pass Criteria
Sub interface state will go down .
#### Test Fail Criteria
Sub interface state still up.

## Test case 1.09 :Ip address removed from asic when unconfiguring dot1q encapsulation
### Description
check IP address in Asic after deconfiguring dot1q encapsulation.
### Test Result Criteria
#### Test Pass Criteria
IP address will remove .
#### Test Fail Criteria
IP address still present .

## Test case 1.10 :Restartability of portd
### Description
restart portd after configuration
### Test Result Criteria
#### Test Pass Criteria
Configuration should be present .
#### Test Fail Criteria
Configurations are irrased .

## Test case 1.11 :verifying configuration afrer system restart
### Description
Check IP address in Asic after deconfiguring dot1q encapsulation.
### Test Result Criteria
#### Test Pass Criteria
Configuration should be present .
#### Test Fail Criteria
Configurations are irrased .

## Test case 1.12 :Subinterface link state when parent interface link state goes down
### Description
Veryfy subinterface link state when parent interface link state goes down.
### Test Result Criteria
#### Test Pass Criteria
Sub interface link state will go down .
#### Test Fail Criteria
Sub interface link state still UP .

## Test case 1.13 :Subinterface link state when parent interface link down to up
### Description
verify Subinterface link state when parent interface no shutdown from shut .
### Test Result Criteria
#### Test Pass Criteria
Sub interface link state will go down .
#### Test Fail Criteria
Sub interface link state still UP .

## Test case 1.14 :Delet subinterface and verify in kernel namespace
### Description
Delet subinterface and verify wether it present in kernel namesapce.
### Test Result Criteria
#### Test Pass Criteria
Sub interface deleted .
#### Test Fail Criteria
Sub interface still present .

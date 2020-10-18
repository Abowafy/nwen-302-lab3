Introduction

SDN is a new approach to the current world of networking, in this lab you will learn basic concepts of SDN through OpenFlow. OpenFlow started with several engineers from Stanford University creating a protocol that would have a logically centralised control plane separated from the underlying switching details. OpenFlow was architected for a number of devices containing only data planes to respond to commands sent to them from a logically centralised controller that housed the single control plane for that network. The controller is responsible for maintaining all of the network paths, as well as programming each of the network devices it controlled. The commands and responses to those commands are described in the OpenFlow protocol.

Key Task 1
Modify simple_switch_13.py to include logic to block traffic between host 2 and host 3.
Key Task 2
Extend simple_switch_13.py to count all traffic going to and originating from host 1.
Key Task 3
Extend simple_switch_13.py to combine Task 1 and Task 2 functionalities. Keep track of all traffic (count the number of packets) originating from each host. If the counter exceeds a specific number, block all the traffic originating from this host for 24 hours. The maximum packet count number should be configured through MAX_COUNT variable.

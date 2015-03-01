# Wireshark dissector for the Festo Control Via Ethernet (CVE) protocol


## Overview

This repository contains a Lua Wireshark dissector for the Festo Control
Via Ethernet (CVE) protocol. This protocol is used by the [Festo CMMO-ST][]
Motor controller series of products.

Message structure in CVE is similar to that used in CANOpen, but runs over
TCP/IP (port 49700). Internal and external device behaviour for the
CMMO-ST is based on the Finite State Automaton defined in [CiA 402][]
(CANopen device profile for drives and motion control). Defined dictionary
objects, as well as bit positions (in for instance the Status and Control
Words) do not seem to follow CiA 402 completely however.

Documentation used:

 1. Motor controller, CMMO-ST [User manual][], doc 8022056, 1301a
 1. Control Via Ethernet (CVE), [application note][], doc 100002


## Installation

### Linux

Copy or symlink the `packet-festo-cve.lua` file to either the Wireshark
global (`/usr/(local/)share/wireshark/plugins`) or per-user
(`$HOME/.wireshark/plugins`) plugin directory.

### Windows

Copy the the `packet-festo-cve.lua` file to either the Wireshark
global (`%WIRESHARK%\plugins`) or per-user (`%APPDATA%\Wireshark\plugins`)
plugin directory.


## Compatible Wireshark versions

The dissector has been extensively used with Wireshark versions 1.11.x and
1.12.x, but is expected to work on most versions with Lua support.


## Configuration

The dissector currently has three configurable options:

 1. Enable validation: this adds some Expert Info to packets which seem
    to be violating protocol specification (as described in the
    [User manual][])
 1. Include unknown bits: should unknown bit positions in the Status Word
    reply be included in the dissection? They will be added as `unknownN`
    fields, with `N` between 0 and 13.
 1. Add CiA 402 bits: should unknown bit positions in the Status Word
    reply be dissected based on their definition in CiA 402? This only applies
    to unknown bits: any positions defined in the [User manual][] will not
    have their descriptions overwritten.



[Festo CMMO-ST]: http://www.festo.com/cat/en-gb_gb/products_CMMO_ST
[CiA 402]: http://www.can-cia.org/index.php?id=530
[User manual]: http://www.festo.com/net/SupportPortal/Files/326589/8022056g1.pdf
[application note]: http://www.festo.com/net/SupportPortal/Files/345406/100002.pdf

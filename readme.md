![alt tag](https://raw.githubusercontent.com/mkorman90/VolatilityBot/master/pics/logo.png)


## Synopsis

VolatilityBot is an automation tool for researchers cuts all the guesswork and manual tasks out of the binary extraction phase,
or to help the investigator in the first steps of performing a memory analysis investigation.
Not only does it automatically extract the executable (exe), but it also fetches all new processes created in memory, code injections, strings, IP addresses, etc.

## Motivation

Part of the work security researchers have to go through when they study new malware or wish to analyse suspicious executables is to extract the binary file and all the different injections and strings decrypted during the malware’s execution.

In the new version of VolatilityBot, a new feature is automated analysis of memory dumps, using heuristics and YARA/Clam AV Scanners (Clam scan coming soon).
This feature is useful for memory analysis at scale. Usually, this initial process is done manually, either of a malware sample, or a memory dump and it can be lengthy and tedious.

## Current features
* Automated analaysis of malware samples (Based on diff-ing between clean memory image and infected one )
  * Extraction of injected code
  * Dump of new processes
  * Yara scan, static analysis, string extraction, etc. on all outputs
+ Deep binary analysis engine... (EXPLAIN)
+ Automated heuristic analysis of memory dumps
  * Detect anomallies using heuristics and dump the relevant code
  * Yara scan, static analysis, string extraction, etc. on all outputs
            
## Coming soon:
* Integration of automated sample analysis with Fakenet-NG
* Clam scan on extracted code 

## Installation

* Go to https://github.com/volatilityfoundation/volatility and install Volatility

* Install radare2 from: https://github.com/radare/radare2.git

* Install VolatilityBot:
```bash
git clone https://github.com/mkorman90/VolatilityBot.git
cd Volatilitybot
python setup.py install
```

### prepare the virtual machines (Currently only vmware.)
1. Create a new virtual machine, with Windows XP up to windows 10 x64.
2. Make sure the machine has windows defender and FW disabled, and has a static IP
3. Install python 3.5
4. Create c:\temp folder, or change the destination folder in config
5. Copy the agent.py from Utils and launch it (you can execute it without the console using pythonw.exe)
6. Take a snapshot of the VM
7. repeat steps 1-6 for as many VMs as you want

### Configuring the host

1. Edit the required parameters, as instructed in the conf/conf.py file
2. Execute gi_build_vbot - in order to build the golden images for all active VMs

###Submit

* Launch the system (execute each command in a new terminal):
```
volatilitybot_d
volatilitybot_post_processing_daemon
volatilitybot_post_processing_workers
```

* Submit an executable and analyze it using Volatility:
```
volatilitybot_submit <Sample Path>
```

* Utils:
    - a
    - b
    - c
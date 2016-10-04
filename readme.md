![alt tag](https://bytebucket.org/martink90/volatilitybot_public/raw/eca82b287aea53bfe308042eec7a713cfcc355b7/pics/logo.png)


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
        + Automated heuristic analysis of memory dumps 
            * Detect anomallies using heuristics and dump the relevant code
            * Yara scan, static analysis, string extraction, etc. on all outputs
            
## Coming soon:
* Integration of automated sample analysis with Fakenet-NG
* Clam scan on extracted code 

## Installation

git clone https://martink90@bitbucket.org/martink90/volatilitybot_public.git

install the required dependencies, from the requirements.txt file

### prepare the VM (Currently only vmware)
1. Create a new virtual machine, with Windows XP up to windows 10 x64.
2. Make sure the machine has windows defender and FW disabled, and has a static IP
3. Install python 3.5
4. Create c:\temp folder, or change the destination folder in config
5. Copy the agent.py from Utils and launch it (you can execute it without the console using pythonw.exe)
6. Take a snapshot of the VM
7. repeat steps 1-6 for as many VMs as you want

### Configuring the host

1. Edit the required parameters, as instructed in the conf/conf.py file
2. Execute db_builder.py - in order to create the database
3. Execute gi_builder.py - in order to build the golden images for all active VMs

###Submit

* Analyze a memory dump using heuristics, and dump output to folder
```
VolatilityBot.py  -m --dump -f /Users/Martin/Downloads/stuxnet.vmem
```

* Submit an executable and analyze it using Volatility:
```
VolatilityBot.py  -f <Sample Path>
VolatilityBot.py  -D
```
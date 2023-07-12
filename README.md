# SecPlus12-21
This Is Study Material Only!

Hardware Root of Trust (ROT)
or trust anchor is a secure subsystem that is able to provide attestation 


Trusted Platform Module (TPM)
ROT is usually established by by a type of cryptoprocessor called a _____________


Secure Boot
Designed to prevent a computer from being hijacked by a malicious OS


Endpoint Detection and Response (EDR)
This products aim is not to prevent initial execution, but to provide real-time and historical visibility into the compromise, contain the malware within a single host, and facilitate remediation of the host to its original state


Z-Wave
Devices can be configured to work as repeater to extend the network but there is a limit of four "hops" between a controller device, and an endpoint


Corporate Owned Business Only (COBO)
This device is the property of the company and may only be used for company business 



Mobile Device Management (MDM) 

Sets the device policies for authentication feature used (camera and microphone), and connectivity. Can also allow device resets, and remote wipes


Bluetooth Device Security Issues 

Device Discovery

Authentication and Authorization 

Malware 



Vertical Privilege Escalation 

Where a user or application can access functionality or data that should not be available to them


Horizontal Privilege Escalation 

Where a user accesses functionality or data that is intended for another user


Replay Attack
Works by sniffing or guessing the token value and then submitting it to re-establish the session illegitimately


Secure Cookies
- Avoid using persistent cookies for session authentication. Always use a new cookie when the user reauthenticates 

- Set the secure attribute to prevent a cookie being sent over unencrypted HTTP

- Set the HttpOnly attribute to make the cookie inaccessible to document object model / client-side scripting

- Use the SameSite attribute to control from where a cookie may be sent mitigating request forgery attacks



Dead Code
Code is executed but has no effect on the program flow


Window Defender Application Control (WDAC)
Formerly device guard this can be used to create code integrity policies, which can be used on their own or in conjunction with AppLocker


Execution of PowerShell Scripts
Can be inhibited by the execution policy, Note that the execution policy is not an access control mechanism. It can be bypassed in any number of different ways. WDAC is a robust mechanism for restricting use of potentially dangerous code, such as malicious PowerShell


Shellcode 

A minimal program designed to exploit a buffer overflow or similar vulnerability to gain privileges, or to drop a backdoor on the host if run as a Trojan


Common Vector For Attacking Linux Hosts
To use an exploit to install a web shell as a backdoor


Software Development Life Cycle (SDLC)
Two principal type : The waterfall model, and Agile Development


A Virtual Platform Requires ___ Components 

3 

Host Hardware

Hypervisor / Virtual Machine Monitor (VMM)

Guest Operation System



VM Escaping 

Refers to malware running on a guest OS jumping to another guest or to the host


Reducing Impact of VM Escaping
The impact of VM escaping can be reduced by using effective service design and network placement when deploying VM's


Indicators of On-Premises Attacks
Found in local application logs and network traffic


Indicators of Cloud Based Attacks
Found in API logs and metrics


Cloud Access Security Broker (CASB)
Enterprise management software designed to mediate access to cloud services by users across all types of devices.


Information Life Cycle Management
Creation / Collection

Distribution / Use 

Retention

Disposal 



Personally Identifiable Information (PII)
Data that can be used to identify, contact, or locate an individual


Data Sovereignty
Refers to a jurisdiction preventing or restricting processing and storage from taking place on systems do not physically reside within that jurisdiction 



Nondisclosure Agreement (NDA)
Legal basis for protecting information assets 



Incident Response Policy 

Sets the resources, processes, and guidelines for dealing with security incidents


Continuity of Operation Plan (COOP)
Refers specifically to backup methods of performing mission functions without IT support 



Metadata
Properties of data as it is created by an application, stored on media, or transmitted over a network


Digital Forensics (Definition)
The practice of collecting evidence from computer systems to a standard that will be accepted in a court of law


First Phase of Forensics Investigation 

Document the scene


Live System
If possible evidence is gathered from the ___________ using forensic software tools


Digital Forensics (Use)
Can be used for information gathering to protect against espionage and hacking


Counterintelligence
Identification and analysis of specific adversary tactics, techniques, and procedures (TTP) provides information about how to configure and audit active logging systems so that they are most likely to capture evidence of attempted and successful intrusions 



Order of Volatility (1)
CPU registers and cache memory (including cache on disc controllers, GPU's, and so on)


Order of Volatility (2)
Contents of non persistent system memory (RAM), including routing table, ARP cache, process table, kernel statistics


Order of Volatility (3)
Data on persistent mass storage devices (HDD's, SSD's and flash memory devices)

- Partition a file system blocks, slack spare, and free space

- System memory caches such as a swap space / virtual memory and hibernation files

- Temporary file caches such as the browser cache

- User application, and OS filed and directories 



Likelihood
__________ of occurrence is the probability of the threat being realized 



Risk Reductuion
Refers to controls that can either make a risk incident less likely or less costly (or both)


Control Risk
A measure of how much less effective a security control has become over time


Recovery Time Objective (RTO)
The period of time following a disaster that an individual IT system may remain offline


Mean Time to Repair (MTTR)
A measure of the time taken to correct a fault so that the system is restored to full operation


Non Persistence 

Any given instance is completely static in terms of processing function 



Mechanisms for Ensuring Non Persistence
Snapshot / Revert to Known State

Rollback to Known Configuration 

Live Boot Media 



Snapshot / Revert to Known State
This is a saved system state that can be reapplied to the instance


Rollback to Known Configuration 

A physical instance might not support snapshots but has an "internal" mechanism for restoring the baseline system configuration, such as Windows System Restore


Live Boot Media 

Another option is to use an instance that boots from read-only storage to memory rather than being installed on a local read/write hard disk


Response and Recovery Controls
Refer to the whole set of policies, procedures and resources created for incident and disaster response and recovery. 



Site Resiliency
Is described as hot, warm, or cold


Hot Site
Can failover immediately. It generally means that the site is already within the organization's ownership and is ready to deploy


Warm Site
Could be similar to a hot site, but with the requirements that the latest data set will need to be loaded


Cold Site 

Takes longer to set up. May be an empty building with a lead agreement in place to install whatever equipment is required when necessary 



Hot Hot
Refers to synchronous replication between the live site and the fail over so that there is no delay


Hot Cold
Refers to a processing facility that is fully operational but where data must be restored manually from a backup


Honeypot
A computer system set up to attract threat actors 


Lock Types
Physical, Electronic , and Biometric 


Physical
A conventional lock prevents the door handle from being operated without the use of a key. More expensive types offer greater resistance against lock picking 


Electronic 

Rather than a key, the lock is operated by entering a PIN on an electronic keypad. This type of lock is also referred to as a cipher, combination, or keyless. A smart lock may be opened using magnetic swipe card or feature a proximity reader


Proximity Reader
Used in smart lock to detect the presence of a physical token, such as a wireless key fob or smart card


Biometric 

A lock may be integrated with a biometric scanner 


Main Types of Alarm
There are 5 main types of alarms : 

Circuit, Motion Detection, Noise Detection, Proximity, and Duress


Circuit 

A circuit-based alarm sounds when the circuit is opened or closed, depending on the type of alarm. (Door, window, or fence opening or closing)


Motion Detection
A motion-based alarm is linked to a detector triggered by any movement within an area (defined by the sensitivity and range of the detector), such as a room


Noise Detection
An alarm triggered by sounds picked up by a microphone. 



Proximity 

Radio frequency ID (RFID) tags and readers can be used to track the movement of tagged objects within an area


Duress
This type of alarm is triggered manually by staff if they come under threat. There are many ways of implementing this type of alarm, including wireless pendants, concealed sensors or triggers, and DECT handsets or smartphones


Protected Distribution System (PDS)
A physically secure cabled network (also referred to as protected cable distribution)


Faraday Cage 

The cage is a charged conductive mesh that blocks signals from entering or leaving the area


Fire Detection
- Well Marked fire exits and an emergency evacuation procedure that is tested and practiced regularly 

- Building design hat does not allow fire to spread quickly, by separating different areas with fire-resistant walls and doors

- Automatic smoke or fire detection systems, as well as alarms that can be operated manually 


Secure Data Destruction
Five Types: 

Burning, Shredding, Pulping, Pulverizing, Degaussing



Degaussing 

Exposing a hard disk to a powerful electro magnetic disrupts the magnetic pattern that stores the data on the disk surface.

NOTE: SSD'S FLASH MEDIA, AND OPTICAL MEDIA CANNOT BE DEGGAUSSED ONLY HARD DISK DRIVES



Pulverizing 

Hitting a hard drive with a hammer can leave a surprising amount of recoverable data so this process should be done with a machine 



Zero Filling
Most basic type of overwriting by setting beach bit to zero. Single pass zero filling can leave patterns that can be read with special tools.


Instant Secure Erase (ISE)
HDD's and SSD's that are self-encrypting drives (SED's) support another option, invoking a SANITIZE command set in SATA and SAS standards from 2012 to perform a crypto erase. Drive vendors implement this as Instant Secure Erase (ISE). With an SED, all data on the drive is encrypted using a media encryption key. When the erase command is issued the MEK is erased, rendering the dada unrecoverable. FIPS140-2 or FIPS140-3 validation provides assurance that the cryptographic implementation is strong. 






![Icon](https://github.com/netevert/pockint/blob/master/docs/icon.png)
=======
[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com) 

[![GitHub release](https://img.shields.io/github/release/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/delator/releases)
[![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/delator/commit/master)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)

POCKINT (a.k.a. Pocket Intelligence) is the OSINT swiss army knife for DFIR professionals and analysts. Designed to be a lightweight and portable GUI program (to be carried within USBs or investigation VMs), it provides users with essential OSINT capabilities in a compact form factor: POCKINTs input box accepts typical indicators (URL, IP, MD5) and gives users the ability to perform basic OSINT data mining tasks in an iterable manner.

![demo](https://github.com/netevert/pockint/blob/master/docs/demo.gif)

** **Thank you for your interest in POCKINT! Please note that POCKINT is currently in BETA. The software is provided for interested users to test the core functionality and features. I am actively looking for feedback and trying to determine potential interest in the tool. If POCKINT is of interest to you please make sure to star the repo. If you'd like to report bugs or would like to request a feature please do so through the [issues page](https://github.com/netevert/pockint/issues) or feel free to write to me on twitter [@netevert](https://twitter.com/netevert).** **

POCKINT is scheduled for v.1.0.0 release by the end of June 2019 for both Windows and Linux platforms.

## Installation

You can grab a testing copy from the [releases page](https://github.com/netevert/pockint/releases). POCKINT is provided as a single executable that can be stored anywhere on computers. Throughout the beta phase POCKINT will be available for Windows only.

## Features

Why use it? POCKINT is designed to be simple, portable and powerful.

**Simple**: There's a plethora of awesome OSINT tools out there. Trouble is they either require analysts to be reasonably comfortable with the command line (think [pOSINT](pOSINThttps://github.com/ecstatic-nobel/pOSINT)) or give you way too many features (think [Maltego](https://www.paterva.com/web7/)). POCKINT focuses on simplicity: INPUT > RUN TRANSFORM > OUTPUT  ... rinse and repeat. It's the ideal tool to get results quickly and easily through a simple interface.

**Portable**: Most tools either require installation, a license or configuration. POCKINT is ready to go whenever and wherever. Put it in your jump kit USBs, investigation VMs or laptop and it will just run. Nobody needs graphs on an incident response :)

**Powerful**: POCKINT combines cheap OSINT sources (whois/DNS) with the power of specialised [APIs](https://www.theguardian.com/media/pda/2007/dec/14/thenutshellabeginnersguide). From the get go you can use a suite of in-built transforms. Add in a couple of API keys and you can unlock even more specialised data mining capabilities.

The beta version is capable of running the following data mining tasks:

<details><summary>Domains</summary>
<p>

* dns: ip lookup
* dns: mx lookup
* dns: txt lookup
* dns: ns lookup
* virustotal: downloaded samples
* virustotal: detected urls
* virustotal: subdomains
  
</p>
</details>
<details><summary>IP Adresses</summary>
<p>

* dns: reverse lookup
* shodan: ports
* shodan: geolocate
* shodan: coordinates
* shodan: cves
* shodan: isp
* shodan: city
* shodan: asn
* virustotal: network report
* virustotal: communicating samples
* virustotal: downloaded samples
* virustotal: detected urls

</p>
</details>
<details><summary>Urls</summary>
<p>

* dns: extract hostname
* virustotal: malicious check
* virustotal: reported detections
  
</p>
</details>
<details><summary>Hashes</summary>
<p>
 
* virustotal: malicious check
* virustotal: malware type

</p>
</details>
<details><summary>Emails</summary>
<p>

* extract domain
  
</p>
</details>

More API and input integrations are planned for the future. Consult the [roadmap](https://github.com/netevert/pockint/milestones) to check out what's brewing or [propose](https://github.com/netevert/pockint/issues) your own favourite API/input.

## Credits

Credit goes to the following people for their contributions to the project, either as providers of early feedback/ideas or for their awesome help in spreading the word:

* [Olaf Hartong](https://twitter.com/olafhartong)
* [Uriel](https://github.com/0x557269656C)
* [Jake Creps](https://twitter.com/jakecreps)
* [Simon Biles](https://twitter.com/si_biles)

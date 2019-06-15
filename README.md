![Icon](https://github.com/netevert/pockint/blob/master/docs/icon.png)
=======
[![forthebadge](https://forthebadge.com/images/badges/made-with-python.svg)](https://forthebadge.com) 

[![GitHub release](https://img.shields.io/github/release/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/pockint/releases)
[![Maintenance](https://img.shields.io/maintenance/yes/2019.svg?style=flat-square)]()
[![GitHub last commit](https://img.shields.io/github/last-commit/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/pockint/commit/master)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)

POCKINT (a.k.a. Pocket Intelligence) is the OSINT swiss army knife for DFIR/OSINT professionals. Designed to be a lightweight and portable GUI program (to be carried within USBs or investigation VMs), it provides users with essential OSINT capabilities in a compact form factor: POCKINT's input box accepts typical indicators (URL, IP, MD5) and gives users the ability to perform basic OSINT data mining tasks in an iterable manner.

![demo](https://github.com/netevert/pockint/blob/master/docs/demo.gif)

## Installation

You can grab the latest version from the [releases page](https://github.com/netevert/pockint/releases). POCKINT is provided as a single executable that can be stored and run anywhere on computers. POCKINT is available for Windows and Linux platforms.

## Features

Why use it? POCKINT is designed to be **simple, portable and powerful**.

**Simple**: There's a plethora of awesome OSINT tools out there. Trouble is they either require analysts to be reasonably comfortable with the command line (think [pOSINT](https://github.com/ecstatic-nobel/pOSINT)) or give you way too many features (think [Maltego](https://www.paterva.com/web7/)). POCKINT focuses on simplicity: _INPUT_ > _RUN TRANSFORM_ > _OUTPUT_  ... rinse and repeat. It's the ideal tool to get results quickly and easily through a simple interface.

**Portable**: Most tools either require installation, a license or configuration. POCKINT is ready to go whenever and wherever. Put it in your jump kit USB, investigation VM or laptop and it will just run.

**Powerful**: POCKINT combines cheap OSINT sources (whois/DNS) with the power of specialised [APIs](https://www.theguardian.com/media/pda/2007/dec/14/thenutshellabeginnersguide). From the get go you can use a suite of in-built transforms. Add in a couple of API keys and you can unlock even more specialised data mining capabilities.

The latest version is capable of running the following data mining tasks:

<details><summary>Domains</summary>
<p>

|Source     |Transform          |
| --------- | ----------------- |
| DNS       | IP lookup         |
| DNS       | MX lookup         |
| DNS       | NS lookup         |
| DNS       | TXT lookup        |
| Virustotal| Downloaded samples|
| Virustotal| Detected URLs     |
| Virustotal| Subdomains        |

</p>
</details>
<details><summary>IP Adresses</summary>
<p>

|Source     |Transform             |
| --------- | -------------------- |
| DNS       | Reverse lookup       |
| Shodan    | Ports                |
| Shodan    | Geolocate            |
| Shodan    | Coordinates          |
| Shodan    | CVEs                 |
| Shodan    | ISP                  |
| Shodan    | City                 |
| Shodan    | ASN                  |
| Virustotal| Network report       |
| Virustotal| Communicating samples|
| Virustotal| Downloaded samples   |
| Virustotal| Detected URLs        |

</p>
</details>
<details><summary>Urls</summary>
<p>

|Source     |Transform             |
| --------- | -------------------- |
| DNS       | Extract hostname     |
| Virustotal| Malicious check      |
| Virustotal| Reported detections  |

</p>
</details>
<details><summary>Hashes</summary>
<p>
 
|Source     |Transform             |
| --------- | -------------------- |
| Virustotal| Malicious check      |
| Virustotal| Malware type         |

</p>
</details>
<details><summary>Emails</summary>
<p>

|Source     |Transform             |
| --------- | -------------------- |
| N/A       | Extract domain       |

</p>
</details>

New APIs and input integrations are constantly being added to the tool. Consult the [roadmap](https://github.com/netevert/pockint/milestones) to check out what's brewing or [propose](https://github.com/netevert/pockint/issues) your own favourite API/input.

## Credits

Credit goes to the following people for their contributions to the project, either as providers of early feedback/ideas or for their awesome help in spreading the word:

* [Olaf Hartong](https://twitter.com/olafhartong)
* [Uriel](https://github.com/0x557269656C)
* [Jake Creps](https://twitter.com/jakecreps)
* [Simon Biles](https://twitter.com/si_biles)

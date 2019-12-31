![Icon](https://github.com/netevert/pockint/blob/master/docs/icon.png)
=======
[![made with python](https://img.shields.io/badge/-made%20with%20python-blue.svg?logo=python&style=flat-square&logoColor=white)](https://www.python.org)
![Supported platforms](https://img.shields.io/badge/platform-Windows%20|%20Linux-informational.svg?style=flat-square)
[![GitHub release](https://img.shields.io/github/release/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/pockint/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/pockint/commit/master)
![GitHub All Releases](https://img.shields.io/github/downloads/netevert/pockint/total.svg?style=flat-square)
[![Twitter Follow](https://img.shields.io/twitter/follow/netevert.svg?style=social)](https://twitter.com/netevert)

POCKINT (a.k.a. Pocket Intelligence) is the OSINT swiss army knife for DFIR/OSINT professionals. A lightweight and portable GUI program, it provides users with essential OSINT capabilities in a compact form factor: POCKINT's input box accepts typical indicators (URL, IP, MD5) and gives users the ability to perform basic OSINT data mining tasks in an iterable manner.

![demo](https://github.com/netevert/pockint/blob/master/docs/demo.gif)

## Installation

You can grab the latest version from the [releases page](https://github.com/netevert/pockint/releases/latest). POCKINT is provided as a single executable that can be stored and run anywhere on computers. POCKINT is available for Windows and Linux platforms.

## Features

Why use it? POCKINT is designed to be **simple, portable and powerful**.

:star: **Simple**: There's a plethora of awesome OSINT tools out there. Trouble is they either require analysts to be reasonably comfortable with the command line (think [pOSINT](https://github.com/ecstatic-nobel/pOSINT)) or give you way too many features (think [Maltego](https://www.paterva.com/web7/)). POCKINT focuses on simplicity: _INPUT_ > _RUN TRANSFORM_ > _OUTPUT_  ... rinse and repeat. It's the ideal tool to get results quickly and easily through a simple interface.

:package: **Portable**: Most tools either require installation, a license or configuration. POCKINT is ready to go whenever and wherever. Put it in your jump kit USB, investigation VM or laptop and it will just run.

:rocket: **Powerful**: POCKINT combines cheap OSINT sources (whois/DNS) with the power of specialised [APIs](https://www.theguardian.com/media/pda/2007/dec/14/thenutshellabeginnersguide). From the get go you can use a suite of in-built transforms. Add in a couple of API keys and you can unlock even more specialised data mining capabilities.

The latest version is capable of running the following data mining tasks:

<details><summary>Domains</summary>
<p>

|Source                                     |Transform               |API key needed?   |
| ----------------------------------------- | ---------------------- | ---------------- |
| DNS                                       | IP lookup              |:x:               |
| DNS                                       | MX lookup              |:x:               |
| DNS                                       | NS lookup              |:x:               |
| DNS                                       | TXT lookup             |:x:               |
| WHOIS                                     | Domain dnssec status   |:x:               |
| WHOIS                                     | Domain creation        |:x:               |
| WHOIS                                     | Domain expiration      |:x:               |
| WHOIS                                     | Domain emails          |:x:               |
| WHOIS                                     | Domain registrar       |:x:               |
| WHOIS                                     | Registrant location    |:x:               |
| WHOIS                                     | Registrant org         |:x:               |
| WHOIS                                     | Registrant name        |:x:               |
| WHOIS                                     | Registrant address     |:x:               |
| WHOIS                                     | Registrant zipcode     |:x:               |
| [crt.sh](https://crt.sh/)                 | Subdomains             |:x:               |
| [Virustotal](https://www.virustotal.com)  | Downloaded samples     |:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Detected URLs          |:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Subdomains             |:heavy_check_mark:|

</p>
</details>
<details><summary>IPv4 Adresses</summary>
<p>

|Source                                     |Transform             |API key needed?   |
| ----------------------------------------- | -------------------- | ---------------- |
| DNS                                       | Reverse lookup       |:x:               |
| [Shodan](https://www.shodan.io/)          | Ports                |:heavy_check_mark:|
| [Shodan](https://www.shodan.io/)          | Geolocate            |:heavy_check_mark:|
| [Shodan](https://www.shodan.io/)          | Coordinates          |:heavy_check_mark:|
| [Shodan](https://www.shodan.io/)          | CVEs                 |:heavy_check_mark:|
| [Shodan](https://www.shodan.io/)          | ISP                  |:heavy_check_mark:|
| [Shodan](https://www.shodan.io/)          | City                 |:heavy_check_mark:|
| [Shodan](https://www.shodan.io/)          | ASN                  |:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Network report       |:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Communicating samples|:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Downloaded samples   |:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Detected URLs        |:heavy_check_mark:|
| [OTX](https://otx.alienvault.com/)        | Malware type         |:heavy_check_mark:|
| [OTX](https://otx.alienvault.com/)        | Malware hash         |:heavy_check_mark:|

</p>
</details>
<details><summary>Urls</summary>
<p>

|Source                                     |Transform             |API key needed?   |
| ----------------------------------------- | -------------------- | ---------------- |
| DNS                                       | Extract hostname     |:x:               |
| [Virustotal](https://www.virustotal.com)  | Malicious check      |:heavy_check_mark:|
| [Virustotal](https://www.virustotal.com)  | Reported detections  |:heavy_check_mark:|

</p>
</details>
<details><summary>MD5 and SHA256 Hashes</summary>
<p>
 
|Source                                      |Transform             |API key needed?   |
| ------------------------------------------ | -------------------- | ---------------- |
|  [Virustotal](https://www.virustotal.com)  | Malicious check      |:heavy_check_mark:|
|  [Virustotal](https://www.virustotal.com)  | Malware type         |:heavy_check_mark:|

</p>
</details>
<details><summary>Emails</summary>
<p>

|Source     |Transform             |API key needed?   |
| --------- | -------------------- | ---------------- |
| N/A       | Extract domain       |:x:               |

</p>
</details>

New APIs and input integrations are in the works, consult the [issues page](https://github.com/netevert/pockint/issues) to check out what's brewing or feel free to propose your own.

Like it?
=========
If you like the tool please consider [contributing](https://github.com/netevert/pockint/blob/master/CONTRIBUTING.md).

The tool received a few "honourable" mentions, including:

- [KitPloit](https://www.kitploit.com/2019/10/pockint-portable-osint-swiss-army-knife.html)
- [kalilinuxtutorials.com](https://kalilinuxtutorials.com/pockint-portable-osint-swiss-army-knife-dfir-osint/)
- [hacking.land](https://www.hacking.land/2019/10/pockint-portable-osint-swiss-army-knife.html)
- [awesomeopensource.com](https://awesomeopensource.com/project/netevert/pockint)

**Please note:** There have been a small number of reports indicating that pockint triggers false positives on antivirus protected systems (to date [Avast, AVG](https://github.com/netevert/pockint/issues/22) and [Norton](https://twitter.com/ChiefCovfefe/status/1204807996028657664)). The issue [seems to be caused by pyinstaller](https://stackoverflow.com/questions/43777106/program-made-with-pyinstaller-now-seen-as-a-trojan-horse-by-avg), the [python package](https://www.pyinstaller.org/) used to freeze and distribute pockint. If pockint triggers your antivirus please submit an issue and the author will submit a false positive report to the concerned antivirus provider.
![Icon](https://github.com/netevert/pockint/blob/master/docs/icon.png)
=======
[![made with python](https://img.shields.io/badge/-made%20with%20python-blue.svg?logo=python&style=flat-square&logoColor=white)](https://www.python.org)
![Supported platforms](https://img.shields.io/badge/platform-Windows%20|%20Linux-informational.svg?style=flat-square)
[![GitHub release](https://img.shields.io/github/release/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/pockint/releases)
[![GitHub last commit](https://img.shields.io/github/last-commit/netevert/pockint.svg?style=flat-square)](https://github.com/netevert/pockint/commit/master)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square&logo=github)](http://makeapullrequest.com)
![GitHub All Releases](https://img.shields.io/github/downloads/netevert/pockint/total.svg?style=flat-square)
[![Twitter Follow](https://img.shields.io/twitter/follow/netevert.svg?style=social)](https://twitter.com/netevert)

POCKINT (a.k.a. Pocket Intelligence) is the OSINT swiss army knife for DFIR/OSINT professionals. Designed to be a lightweight and portable GUI program (to be carried within USBs or investigation VMs), it provides users with essential OSINT capabilities in a compact form factor: POCKINT's input box accepts typical indicators (URL, IP, MD5) and gives users the ability to perform basic OSINT data mining tasks in an iterable manner.

![demo](https://github.com/netevert/pockint/blob/master/docs/demo.gif)

## Installation

You can grab the latest version from the [releases page](https://github.com/netevert/pockint/releases). POCKINT is provided as a single executable that can be stored and run anywhere on computers. POCKINT is available for Windows and Linux platforms.

## Features

Why use it? POCKINT is designed to be **simple, portable and powerful**.

 :ok_hand: **Simple**: There's a plethora of awesome OSINT tools out there. Trouble is they either require analysts to be reasonably comfortable with the command line (think [pOSINT](https://github.com/ecstatic-nobel/pOSINT)) or give you way too many features (think [Maltego](https://www.paterva.com/web7/)). POCKINT focuses on simplicity: _INPUT_ > _RUN TRANSFORM_ > _OUTPUT_  ... rinse and repeat. It's the ideal tool to get results quickly and easily through a simple interface.

 :package: **Portable**: Most tools either require installation, a license or configuration. POCKINT is ready to go whenever and wherever. Put it in your jump kit USB, investigation VM or laptop and it will just run.

 :rocket: **Powerful**: POCKINT combines cheap OSINT sources (whois/DNS) with the power of specialised [APIs](https://www.theguardian.com/media/pda/2007/dec/14/thenutshellabeginnersguide). From the get go you can use a suite of in-built transforms. Add in a couple of API keys and you can unlock even more specialised data mining capabilities.

The latest version is capable of running the following data mining tasks:

<details><summary>Domains</summary>
<p>

|Source     |Transform          |API key needed?   |
| --------- | ----------------- | ---------------- |
| DNS       | IP lookup         |:x:               |
| DNS       | MX lookup         |:x:               |
| DNS       | NS lookup         |:x:               |
| DNS       | TXT lookup        |:x:               |
| Virustotal| Downloaded samples|:heavy_check_mark:|
| Virustotal| Detected URLs     |:heavy_check_mark:|
| Virustotal| Subdomains        |:heavy_check_mark:|

</p>
</details>
<details><summary>IP Adresses</summary>
<p>

|Source     |Transform             |API key needed?   |
| --------- | -------------------- | ---------------- |
| DNS       | Reverse lookup       |:x:               |
| Shodan    | Ports                |:heavy_check_mark:|
| Shodan    | Geolocate            |:heavy_check_mark:|
| Shodan    | Coordinates          |:heavy_check_mark:|
| Shodan    | CVEs                 |:heavy_check_mark:|
| Shodan    | ISP                  |:heavy_check_mark:|
| Shodan    | City                 |:heavy_check_mark:|
| Shodan    | ASN                  |:heavy_check_mark:|
| Virustotal| Network report       |:heavy_check_mark:|
| Virustotal| Communicating samples|:heavy_check_mark:|
| Virustotal| Downloaded samples   |:heavy_check_mark:|
| Virustotal| Detected URLs        |:heavy_check_mark:|

</p>
</details>
<details><summary>Urls</summary>
<p>

|Source     |Transform             |API key needed?   |
| --------- | -------------------- | ---------------- |
| DNS       | Extract hostname     |:x:               |
| Virustotal| Malicious check      |:heavy_check_mark:|
| Virustotal| Reported detections  |:heavy_check_mark:|

</p>
</details>
<details><summary>Hashes</summary>
<p>
 
|Source     |Transform             |API key needed?   |
| --------- | -------------------- | ---------------- |
| Virustotal| Malicious check      |:heavy_check_mark:|
| Virustotal| Malware type         |:heavy_check_mark:|

</p>
</details>
<details><summary>Emails</summary>
<p>

|Source     |Transform             |API key needed?   |
| --------- | -------------------- | ---------------- |
| N/A       | Extract domain       |:x:               |

</p>
</details>

New APIs and input integrations are constantly being added to the tool. Consult the [roadmap](https://github.com/netevert/pockint/milestones) to check out what's brewing or [propose](https://github.com/netevert/pockint/issues) your own favourite API/input.

## Credits

Credit goes to the following people for their contributions to the project, either as providers of early feedback/ideas or for their awesome help in spreading the word:

* [Olaf Hartong](https://twitter.com/olafhartong)
* [Uriel](https://github.com/0x557269656C)
* [Jake Creps](https://twitter.com/jakecreps)
* [Simon Biles](https://twitter.com/si_biles)

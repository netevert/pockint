#!/usr/bin/env python

import base64
import dns.resolver
import IndicatorTypes
import json
import os
from OTXv2 import OTXv2
import re
import requests
import socket as sock
import shodan
import sqlite3
import sys
import tempfile
from urllib.parse import urlparse
import validators
import webbrowser
import whois

class Database(object):
    """Local sqlite database handler class"""
    def __init__(self):
        """Initialises application database, if app db doesn't exist, it creates one"""
        
        # verify that db folder exists, if not create one
        if sys.platform == "win32":
            self.db_path = os.getenv("LOCALAPPDATA")+ "\\pockint\\"
        else:
            self.db_path = os.path.expanduser(os.path.join("~", ".pockint"))
        if not os.path.exists(self.db_path):
            os.makedirs(self.db_path)
            self.create_database()
        
        # connect to database
        self.db = sqlite3.connect(self.db_path + "\\.pockint.db")
        self.cursor = self.db.cursor()

        # create json_data table if not exist (to upgrade old databases)
        self.cursor.execute("""SELECT name FROM sqlite_master WHERE type='table' AND name='json_data';""")
        if not self.cursor.fetchone():
            self.cursor.execute('''CREATE TABLE json_data (id INTEGER PRIMARY KEY, 
            investigation_id TEXT, json TEXT)''')
            self.db.commit()

    def create_database(self):
        """Creates a new database in AppData/Local"""
        db = sqlite3.connect(self.db_path + "\\.pockint.db")
        cursor = db.cursor()
        try:
            cursor.execute('''CREATE TABLE api_keys(id INTEGER PRIMARY KEY, api_name TEXT,
                        api_key TEXT, status INTEGER)''')
            init_data = [("virustotal", "", 0), ("shodan", "", 0), ("OTX DirectConnect API", "", 0)]
            cursor.executemany(''' INSERT INTO api_keys(api_name, api_key, status) VALUES(?,?,?)''', init_data)
            db.commit()
            cursor.execute('''CREATE TABLE json_data (id INTEGER PRIMARY KEY, 
            investigation_id TEXT, json TEXT)''')
            db.commit()
            db.close()
        except sqlite3.Error:
            db.rollback()

    def insert_api_key(self, api: str, _key: str):
        """Updates the api key value and status for the given api"""
        try:
            if _key:
                self.cursor.execute('''UPDATE api_keys SET api_key=?, status=1 WHERE api_name=?''', (_key, api))
                self.db.commit()
            if not _key:
                self.cursor.execute('''UPDATE api_keys SET api_key=?, status=0 WHERE api_name=?''', (_key, api))
                self.db.commit()
        except sqlite3.Error:
            self.db.rollback()

    def get_api_key(self, api: str):
        """Returns the api key for the supplied api name"""
        try:
            self.cursor.execute('''SELECT api_key FROM api_keys WHERE api_name=?''', (api,))
            return self.cursor.fetchone()[0]
        except sqlite3.Error:
            self.db.rollback()

    def get_available_apis(self):
        """Returns api's that have an associated api key"""
        try:
            self.cursor.execute('''SELECT api_name FROM api_keys WHERE status=1''')
            return [api[0] for api in self.cursor.fetchall()]
        except sqlite3.Error:
            self.db.rollback()

    def get_apis(self):
        """Returns all api's available in the database"""
        try:
            self.cursor.execute('''SELECT api_name FROM api_keys''')
            return [api[0] for api in self.cursor.fetchall()]
        except sqlite3.Error:
            self.db.rollback()

    def store_investigation(self, investigation_id, data):
        """Stores investigation data in tab by investigation_id"""
        data = json.dumps(data)
        try:
            self.cursor.execute('''SELECT * FROM json_data WHERE investigation_id=?''', (investigation_id,))
            if not self.cursor.fetchone():
                # insert fresh data
                self.cursor.execute('''INSERT INTO json_data(investigation_id, json) Values (?,?)''', 
                (investigation_id, data))
            else:
                # update data
                self.cursor.execute('''UPDATE json_data SET json=? WHERE investigation_id=?''',
                (data, investigation_id))
            self.db.commit()
        except sqlite3.Error:
            self.db.rollback()

    def delete_investigation(self, investigation_id):
        """Delete investigation data"""
        try:
            self.cursor.execute('''DELETE FROM json_data WHERE investigation_id=?''', (investigation_id,))
            self.db.commit()
        except sqlite3.Error:
            self.db.rollback()

    def open_investigation(self, investigation_id):
        """Retrieves investigation data by investigation_id returning"""
        try:
            self.cursor.execute('''SELECT * FROM json_data WHERE investigation_id=?''', (investigation_id,))
            response = self.cursor.fetchone()
            investigation_id = response[1]
            data = response[2]
        except sqlite3.Error:
            self.db.rollback()

        return [investigation_id, json.loads(data)]

    def retrieve_investigation_ids(self):
        """Retrieves investigation ids from database"""
        try:
            self.cursor.execute('''SELECT investigation_id FROM json_data''')
            data = [row[0] for row in self.cursor.fetchall()]
            return data
        except sqlite3.Error:
            self.db.rollback()

    def close_connection(self):
        """Closes the connection to the local database file"""
        self.db.close()


class Sha256Hash(object):
    """Md5 hash handler class"""
    def __init__(self):
        self.osint_options = {}
        self.api_db = Database()
        self.virustotal_api_key = self.api_db.get_api_key("virustotal")
        if self.virustotal_api_key:
            self.osint_options.update({ 
                "virustotal: malicious check": self.virustotal_is_malicious,
                "virustotal: malware type": self.virustotal_malware_type})
    
    def is_sha256(self, _input: str):
        """Validates if _input is an md5 hash"""
        if validators.hashes.sha256(_input):
            return True
        return False

    def virustotal_is_malicious(self, _hash:str):
        """Checks virustotal to see if sha256 has positive detections"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/file/report",
                self.virustotal_api_key,
                {"resource": _hash}
            )
            if data:
                if data.json().get("response_code") == 0:
                    return ["no report available"]
                return ["hash malicious: {} detections".format(data.json().get("positives"))]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def virustotal_malware_type(self, _hash:str):
        """Checks virustotal to return malware types detected by scans"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/file/report",
                self.virustotal_api_key,
                {"resource": _hash}
            )
            if data:
                if data.json().get("response_code") == 1:
                    return ["{}: {}".format(i, data.json().get("scans").get(i).get("result")) 
                    for i in data.json().get("scans") 
                    if data.json().get("scans").get(i).get("result")]
                return ["no report available"]
            else:
                return ["no data available"]
        except Exception as e:
            return e


class Md5Hash(object):
    """Md5 hash handler class"""
    def __init__(self):
        self.osint_options = {}
        self.api_db = Database()
        self.virustotal_api_key = self.api_db.get_api_key("virustotal")
        if self.virustotal_api_key:
            self.osint_options.update({
                "virustotal: malicious check": self.virustotal_is_malicious,
                "virustotal: malware type": self.virustotal_malware_type})

    def is_md5(self, _input: str):
        """Validates if _input is an md5 hash"""
        if validators.hashes.md5(_input):
            return True
        return False

    def virustotal_is_malicious(self, _hash:str):
        """Checks virustotal to see if MD5 has positive detections"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/file/report",
                self.virustotal_api_key,
                {"resource": _hash}
            )
            if data:
                if data.json().get("response_code") == 0:
                    return ["no report available"]
                return ["hash malicious: {} detections".format(data.json().get("positives"))]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def virustotal_malware_type(self, _hash:str):
        """Checks virustotal to return malware types detected by scans"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/file/report",
                self.virustotal_api_key,
                {"resource": _hash}
            )
            if data:
                if data.json().get("response_code") == 1:
                    return ["{}: {}".format(i, data.json().get("scans").get(i).get("result")) 
                    for i in data.json().get("scans") 
                    if data.json().get("scans").get(i).get("result")]
                return ["no report available"]
            else:
                return ["no data available"]
        except Exception as e:
            return e


class Url(object):
    """Url handler class"""
    def __init__(self):
        self.osint_options = {
            "dns: extract hostname": self.url_to_hostname
        }
        self.api_db = Database()
        self.virustotal_api_key = self.api_db.get_api_key("virustotal")
        if self.virustotal_api_key:
            self.osint_options.update({
                "virustotal: malicious check": self.is_malicious,
                "virustotal: reported detections": self.reported_detections})

    def is_url(self, _input: str):
        """Validates if _input is a url"""
        if validators.url(_input):
            return True
        return False

    def is_malicious(self, url: str):
        """Checks if url is malicious"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/url/report",
                self.virustotal_api_key,
                {"resource": url}
            )
            if data:
                if data.json().get("response_code") == 1:
                    return ["url malicious: {} detections".format(data.json().get("positives"))]
                return ["no report available"]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def reported_detections(self, url: str):
        """Checks virustotal to determine which sites are reporting the url"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/url/report",
                self.virustotal_api_key,
                {"resource": url}
            )
            if data:
                if data.json().get("response_code") == 1:
                    return ["{}: {}".format(i, data.json().get("scans").get(i).get("result"))
                    for i in data.json().get("scans")
                    if (data.json().get("scans").get(i).get("result") == "malicious site") or  
                    (data.json().get("scans").get(i).get("result") == "malware site")]
                return ["no report available"]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def url_to_hostname(self, url: str):
        """Extracts hostname from url"""
        try:
            return [urlparse(url).netloc]
        except Exception as e:
            return e


class IPAdress(object):
    """Ipv4 address handler class"""
    def __init__(self):
        self.osint_options = {
            "dns: reverse lookup": self.reverse_lookup,
            # "dns: ip to asn": self.ip_to_asn,
        }
        self.api_db = Database()
        shodan_api_key = self.api_db.get_api_key("shodan")
        if shodan_api_key:
            self.shodan_api = shodan.Shodan(shodan_api_key)
            self.osint_options.update({
            "shodan: ports": self.ip_to_shodan_ports,
            "shodan: geolocate": self.ip_to_shodan_country_name,
            "shodan: coordinates": self.ip_to_shodan_coordinates,
            "shodan: cve's": self.ip_to_shodan_cves,
            "shodan: isp": self.ip_to_shodan_isp,
            "shodan: city": self.ip_to_shodan_city,
            "shodan: asn": self.ip_to_shodan_asn})
        self.virustotal_api_key = self.api_db.get_api_key("virustotal")
        if self.virustotal_api_key:
            self.osint_options.update({
                "virustotal: network report": self.ip_to_vt_network_report,
                "virustotal: communicating samples": self.ip_to_vt_communicating_samples,
                "virustotal: downloaded samples": self.ip_to_vt_downloaded_samples,
                "virustotal: detected urls": self.ip_to_vt_detected_urls
            })

    def is_ip_address(self, _input: str):
        """Validates if _input is ip address"""
        try:
            sock.inet_aton(_input)
            return True
        except sock.error:
            return False

    def reverse_lookup(self, ip: str):
        """Returns PTR record for ip"""
        try:
            return [sock.gethostbyaddr(ip)[0]]
        except Exception as e:
            if "host not found" in str(e):
                return ["host not found, PTR record likely missing"]
            else:
                return e
    
    def ip_to_asn(self):
        pass

    def ip_to_shodan_ports(self, ip:str):
        """Searches shodan to see if any ports are open on the target ip"""
        try:
            data = self.shodan_api.host(ip)["ports"]
            if data:
                return data
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_shodan_country_name(self, ip:str):
        """Searches shodan to determine the target ip's location"""
        try:
            data = self.shodan_api.host(ip)["country_name"]
            if data:
                return [data]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_shodan_coordinates(self, ip:str):
        """Searches shodan to determine the target ip's location co-ordinates"""
        try:
            latitude, longitude = self.shodan_api.host(ip)["latitude"], self.shodan_api.host(ip)["longitude"]
            if latitude and longitude:
                return [str(latitude) + "," + str(longitude)]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_shodan_cves(self, ip:str):
        """Searches shodan to determine if the ip is vulnerable to CVE's"""
        try:
            vulns = self.shodan_api.host(ip)["vulns"]
            if vulns:
                return vulns
            else:
                return ["no data available"]
        except Exception as e:
            return e
    
    def ip_to_shodan_isp(self, ip:str):
        """Searches shodan to determine the ip's ISP"""
        try:
            isp = self.shodan_api.host(ip)["isp"]
            if isp:
                return [isp]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_shodan_city(self, ip:str):
        """Searches shodan to determine the ip's ISP"""
        try:
            city = self.shodan_api.host(ip)["city"]
            if city:
                return [city]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_shodan_asn(self, ip:str):
        """Searches shodan to determine the ip's ASN"""
        try:
            asn = self.shodan_api.host(ip)["asn"]
            if asn:
                return [asn]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_vt_network_report(self, ip:str):
        """Searches virustotal to return an ip network report"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/ip-address/report",
                self.virustotal_api_key,
                {"ip":ip}
            )
            if data:
                return ["asn owner: {}".format(data.json().get("as_owner")),
                "asn: {}".format(data.json().get("asn")),
                "continent: {}".format(data.json().get("continent")),
                "country: {}".format(data.json().get("country")),
                "network: {}".format(data.json().get("network")),
                "whois: {}".format(data.json().get("whois"))
                ]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def ip_to_vt_communicating_samples(self, ip:str):
        """Searches virustotal to search for detected communicating samples"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/ip-address/report",
                self.virustotal_api_key,
                {"ip":ip})
            if data:
                return [record.get("sha256") for record in data.json()["detected_communicating_samples"]]
            else:
                return ["no data available"]
        except Exception as e:
            return e
    
    def ip_to_vt_downloaded_samples(self, ip:str):
        """Searches virustotal to search for detected communicating samples"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/ip-address/report",
                self.virustotal_api_key,
                {"ip":ip})
            if data:
                return [record.get("sha256") for record in data.json()["detected_downloaded_samples"]]
            else:
                return ["no data available"]
        except Exception as e:
            return e
    
    def ip_to_vt_detected_urls(self, ip:str):
        """Searches virustotal to search for detected communicating samples"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/ip-address/report",
                self.virustotal_api_key,
                {"ip":ip})
            if data:
                return [record.get("url") for record in data.json()["detected_urls"]]
            else:
                return ["no data available"]
        except Exception as e:
            return e


class EmailAddress(object):
    """Email address handler class"""
    def __init__(self):
        self.osint_options = {
            "extract domain": self.domain_extract
        }

    def is_valid_email(self, _input: str):
        """Checks if _input is a valid email"""
        if re.match(r'^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', _input):
            return True
        return False
    
    def hibp_lookup(self):
        pass

    def domain_extract(self, email: str):
        """Returns domain from supplied email"""
        return [email.split("@")[1]]


class Domain(object):
    """Domain handler class"""
    def __init__(self):
        self.osint_options = {
            "dns: ip lookup" : self.to_a_record,
            "dns: mx lookup" : self.to_mx_records,
            "dns: ns lookup" : self.to_ns_records,
            "dns: txt lookup": self.to_txt_records,
            "whois: emails": self.domain_to_whois_emails,
            "whois: location": self.domain_to_whois_location,
            "whois: creation": self.domain_to_whois_creation_date,
            "whois: registrar": self.domain_to_whois_registrar,
            "whois: expiration": self.domain_to_whois_expiration_date,
            "whois: dnssec status": self.domain_to_whois_dnssec_status,
            "whois: registrant org": self.domain_to_whois_registrant_org,
            "whois: registrant name": self.domain_to_whois_registrant_name,
            "whois: registrant address": self.domain_to_whois_registrant_address,
            "whois: registrant zipcode": self.domain_to_whois_registrant_zipcode,
            "crt.sh: subdomains" : self.domain_to_subdomains
        }
        self.api_db = Database()
        shodan_api_key = self.api_db.get_api_key("shodan")
        if shodan_api_key:
            self.shodan_api = shodan.Shodan(shodan_api_key)
            self.osint_options.update({"shodan: hostnames": self.to_shodan_hostnames})
        self.virustotal_api_key = self.api_db.get_api_key("virustotal")
        if self.virustotal_api_key:
            self.osint_options.update({
                "virustotal: downloaded samples": self.domain_to_vt_downloaded_samples,
                "virustotal: detected urls": self.domain_to_vt_detected_urls,
                "virustotal: subdomains": self.domain_to_vt_subdomains
            })

    def is_valid_domain(self, _input: str):
        """Checks if _input is a domain"""
        if re.match(r'^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$', _input):
            return True
        return False
    
    def to_a_record(self, domain: str):
        """Returns dns a record for domain"""
        try:
            return [sock.gethostbyname(domain)]
        except Exception as e:
            return e

    def to_mx_records(self, domain: str):
        """Returns dns mx record for domain"""
        try:
            return [x.exchange for x in dns.resolver.query(domain, 'MX')]
        except Exception as e:
            return e

    def to_txt_records(self, domain: str):
        """Returns dns txt record for domain"""
        try:
            return [x.to_text() for x in dns.resolver.query(domain, 'TXT')]
        except Exception as e:
            return e

    def to_ns_records(self, domain: str):
        """Returns ns record for domain"""
        try:
            return [x.to_text() for x in dns.resolver.query(domain, 'NS')]
        except Exception as e:
            return e

    def to_shodan_hostnames(self, domain: str):
        """Searches shodan to discover hostnames associated with the domain"""
        try:
            data = []
            results = self.shodan_api.search("hostname:{}".format(domain))
            if results:
                for r in results["matches"]:
                    for h in r["hostnames"]:
                        data.append(h)
                return data
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def domain_to_vt_detected_urls(self, domain:str):
        """Searches virustotal to search for detected communicating samples"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/domain/report",
                self.virustotal_api_key,
                {"domain":domain})
            if data:
                return [record.get("url") for record in data.json()["detected_urls"]]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def domain_to_vt_downloaded_samples(self, domain:str):
        """Searches virustotal to search for detected communicating samples"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/domain/report",
                self.virustotal_api_key,
                {"domain":domain})
            if data:
                return [record.get("sha256") for record in data.json()["detected_downloaded_samples"]]
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def domain_to_vt_subdomains(self, domain: str):
        """Searches virustotal for subdomains"""
        try:
            data = make_vt_api_request(
                "https://www.virustotal.com/vtapi/v2/domain/report",
                self.virustotal_api_key,
                {"domain":domain})
            if data:
                return data.json().get("subdomains")
            else:
                return ["no data available"]
        except Exception as e:
            return e

    def domain_to_subdomains(self, domain: str):
        """Discovers subdomains from domain using certificate transparency logs on crt.sh"""
        try:
            req = requests.get("https://crt.sh/?q=%.{d}&output=json".format(d=domain))
            if req.status_code == 200:
                return list({value['name_value'] for (key,value) in enumerate(req.json())})
            else: 
                return ["no data returned from crt.sh"]
        except Exception as e:
            return e

    def domain_to_whois_expiration_date(self, domain: str):
        """Queries whois record to find domain expiration date"""
        try:
            date = str(whois.whois(domain).expiration_date)
            if date:
                return [date]
            else:
                return ["no expiration date returned from whois"]
        except Exception as e:
            return e

    def domain_to_whois_creation_date(self, domain: str):
        """Queries whois record to find domain creation date"""
        try:
            date = str(whois.whois(domain).creation_date)
            if date:
                return [date]
            else:
                return ["no creation date returned from whois"]
        except Exception as e:
            return e

    def domain_to_whois_emails(self, domain: str):
        """Queries whois record to find email data"""
        try:
            data = str(whois.whois(domain).emails)
            if data:
                return [data]
            else:
                return ["no email data returned from whois"]
        except Exception as e:
            return e
    
    def domain_to_whois_registrar(self, domain: str):
        """Queries whois record to find domain registrar data"""
        try:
            data = str(whois.whois(domain).registrar)
            if data:
                return [data]
            else:
                return ["no registrar data returned from whois"]
        except Exception as e:
            return e
    
    def domain_to_whois_location(self, domain: str):
        """Queries whois record to find domain location data"""
        try:
            data = []
            data.append(str(whois.whois(domain).state))
            data.append(str(whois.whois(domain).country))
            if data[0] == "None" and data[1] == "None":
                return ["None"]
            else:
                return [" ".join(data)]
        except Exception as e:
            return e
    
    def domain_to_whois_registrant_org(self, domain: str):
        """Queries whois record to find domain registrant org"""
        try:
            data = str(whois.whois(domain).org)
            if data:
                return [data]
            else:
                return ["no registrant org data returned from whois"]
        except Exception as e:
            return e

    def domain_to_whois_registrant_name(self, domain: str):
        """Queries whois record to find domain registrant name"""
        try:
            data = str(whois.whois(domain).name)
            if data:
                return [data]
            else:
                return ["no registrant name returned from whois"]
        except Exception as e:
            return e

    def domain_to_whois_registrant_address(self, domain: str):
        """Queries whois record to find domain registrant address"""
        try:
            data = str(whois.whois(domain).address)
            if data:
                return [data]
            else:
                return ["no registrant address returned from whois"]
        except Exception as e:
            return e

    def domain_to_whois_registrant_zipcode(self, domain: str):
        """Queries whois record to find domain registrant zipcode"""
        try:
            data = str(whois.whois(domain).zipcode)
            if data:
                return [data]
            else:
                return ["no registrant zipcode returned from whois"]
        except Exception as e:
            return e

    def domain_to_whois_dnssec_status(self, domain: str):
        """Queries whois record to find domain dnssec status"""
        try:
            data = str(whois.whois(domain).dnssec)
            if data:
                return [data]
            else:
                return ["no dnssec status data returned from whois"]
        except Exception as e:
            return e


class InputValidator(object):
    """Handler to validate user inputs"""
    def __init__(self):
        self.ip = IPAdress()
        self.email = EmailAddress()
        self.domain = Domain()
        self.url = Url()
        self.md5 = Md5Hash()
        self.sha256 = Sha256Hash()

    def run(self, _function, **kwargs):
        """Runs function and associated keyword arguments"""
        try:
            return _function(**kwargs)
        except Exception as e:
            return e

    def consistency_check(self, entity_list, entity_type):
        """Ensures that a list of inputs contains the same entities"""
        if not entity_list:
            entity_list.append(entity_type)
        if entity_type in entity_list:
            return True
        return False

    def validate(self, _input: str):
        """Functions to validate user inputs"""
        _input = _input.split(",")
        _list = []
        output = []
        for i in _input:
            if self.ip.is_ip_address(i) and self.consistency_check(_list, "ip"):
                output.append([True, "input: ipv4 address", [option for option in self.ip.osint_options.keys()]])
            elif self.email.is_valid_email(i) and self.consistency_check(_list, "email"):
                output.append([True, "input: email address", [option for option in self.email.osint_options.keys()]])
            elif self.domain.is_valid_domain(i) and self.consistency_check(_list, "domain"):
                output.append([True, "input: domain", [option for option in self.domain.osint_options.keys()]])
            elif self.url.is_url(i) and self.consistency_check(_list, "url"):
                output.append([True, "input: url", [option for option in self.url.osint_options.keys()]])
            elif self.md5.is_md5(i) and self.consistency_check(_list, "hash"):
                output.append([True, "input: md5", [option for option in self.md5.osint_options.keys()]])
            elif self.sha256.is_sha256(i) and self.consistency_check(_list, "hash"):
                output.append([True, "input: sha256", [option for option in self.sha256.osint_options.keys()]])
            else:
                output.append([False, []])
        return output

    def execute_transform(self, _input: str, transform: str):
        """Function to run osint data mining tasks appropriate to each input"""
        if self.ip.is_ip_address(_input):
            return self.run(self.ip.osint_options.get(transform), ip=_input)
        elif self.email.is_valid_email(_input):
            return self.run(self.email.osint_options.get(transform), email=_input)
        elif self.domain.is_valid_domain(_input):
            return self.run(self.domain.osint_options.get(transform), domain=_input)
        elif self.md5.is_md5(_input):
            return self.run(self.md5.osint_options.get(transform), _hash=_input)
        elif self.url.is_url(_input):
            return self.run(self.url.osint_options.get(transform), url=_input)
        elif self.sha256.is_sha256(_input):
            return self.run(self.sha256.osint_options.get(transform), _hash=_input)

def load_icon():
    """loads and returns program icon from base64 string"""
    # workaround from https://stackoverflow.com/questions/9929479/embed-icon-in-python-script
    icondata = base64.b64decode(icon)
    tempFile = tempfile.gettempdir() + "icon.ico"
    iconfile = open(tempFile,"wb")
    ## Extract the icon
    iconfile.write(icondata)
    iconfile.close()
    return tempFile

def make_vt_api_request(url: str, api_key: str, search_params: dict):
    """Helper function to query virustotal public api"""
    try:
        params = {"apikey": api_key}
        params.update(search_params)
        headers = {'User-Agent': 'Pockint v.1.0.0'}
        return requests.get(url, params=params, headers=headers)
    except Exception as e:
        return e

def connect_to_otx_api(otx_server: str, api_key: str):
    """Helper function to connect to alienvault otx directconnect api"""
    try:
        otx = OTXv2(api_key, server=otx_server)
        return otx
    except Exception as e:
        return e

def callback(url):
    webbrowser.open_new(url)

icon = \
"""
AAABAAEAgIAAAAEAIAAoCAEAFgAAACgAAACAAAAAAAEAAAEAIAAAAAAAAAABABILAAASCwAAAAAA
AAAAAAD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AAAAABEAAAA3AAAATQAAAGIAAAB4AAAAjQAAAKMAAAC4AAAAzQAAANUAAADQ
AAAAywAAAMYAAADBAAAAvAAAALYAAACxAAAArAAAAKcAAACiAAAAnQAAAJcAAACSAAAAjQAAAIcA
AABqAAAARgAAACIAAAAD////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAADwAAADkAAABk
AAAAjwAAALoAAADlAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAA
AP8AAAD/AAAA/wAAAPoAAADaAAAAtgAAAJIAAABuAAAASgAAACYAAAAF////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AAAAABUAAABUAAAAlAAAANQAAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAH/AAAQ/wAAI/8AADX/AABI/gAAWv4AAGP+AABf/gAA
Wv4AAFb+AABS/gAATf4AAEn+AABE/gAAQP4AADv+AAA3/gAAM/8AAC7/AAAp/wAAJf8AABv/AAAD
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPwAAADeAAAAugAAAJYAAABv
AAAANQAAAAP///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wAAAAAOAAAAVQAAAJUAAADVAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAC/wAA
Hv8AAEL+AABm/gAAi/4AAK/9AADF/QAA1v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANX9
AAC5/QAAmv4AAHv+AABd/gAAPv4AACD/AAAE/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8A
AAD/AAAA8wAAALgAAAB6AAAAPAAAAAb///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAA
AAsAAABZAAAAsAAAAPgAAAD/AAAA/wAAAP8AAAD/AAAA/wAAGP8AAE7+AACF/gAArv0AANH9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANb9AAC8/QAAnv4AAH7+AABf/gAAQf4AACP/AAAF/wAA
AP8AAAD/AAAA/wAAAP8AAAD/AAAA9wAAAL0AAABsAAAAGv///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAACQAAAFQAAACrAAAA
9gAAAP8AAAD/AAAA/wAAAP8AABb/AABM/gAAhP4AALr9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANL9AACi
/gAAbP4AADf+AAAI/wAAAP8AAAD/AAAA/wAAAP8AAAD+AAAAxAAAAHEAAAAe////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAGQAAAIQAAADrAAAA/wAAAP8AAAD/
AAAA/wAAHv8AAGj+AACx/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANT9AACm/QAAcP4AAC//AAAB/wAAAP8AAAD/AAAA/wAAAP8AAADJAAAAZAAAAAj/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8AAAAAMgAAAKMAAAD6AAAA/wAAAP8AAAD/AAAa/wAAY/4A
AK79AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAMH9AAB5/gAAM/8AAAL/AAAA/wAAAP8AAAD/AAAA6gAA
AIIAAAAX////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8AAAAASgAAAMIAAAD/AAAA/wAAAP8AAAT/AABM/gAAqP0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAxP0AAH3+AAAp/wAAAP8AAAD/AAAA
/wAAAPkAAACfAAAALP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8AAAAALwAAALwAAAD/AAAA/wAAAP8AABD/AABn/gAAw/0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AACk/QAARf4AAAP/
AAAA/wAAAP8AAAD9AAAAlQAAABD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAA
GQAAAJ0AAAD9AAAA/wAAAP8AACD/AACD/gAA0f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAvf0A
AGH+AAAM/wAAAP8AAAD/AAAA6QAAAF8AAAAB////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAABQAAAH0AAAD0
AAAA/wAAAP8AABD/AAB7/gAA1v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AAMb9AABR/gAAAf8AAAD/AAAA/wAAAMQAAAAk////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAACMAAADKAAAA/wAAAP8A
AAX/AABg/gAAzP0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AACo/QAAKf8AAAD/AAAA/wAAAOsAAAA3////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wAAAABbAAAA8gAAAP8AAAD/AAA//gAA
uv0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADX/QAAef4AAAP/AAAA/wAAAPUAAABM////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wAAAAAMAAAAoQAAAP8AAAD/AAAH/wAAfP4AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAAnv4AAAz/AAAA/wAAAPwAAABj////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8AAAAAFQAAAM8AAAD/AAAA/wAAI/8AALH9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAs/0AABn/AAAA/wAAAPwAAAA3////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AAAAABoAAADWAAAA/wAAAP8AAFX+AADR/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAwf0AAA7/AAAA/wAAANYAAAAH////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wAAAAAfAAAA3AAAAP8AAAD/AABy/gAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAi/4AAAD/AAAA/wAAAIb///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8AAAAAHAAAAOIAAAD/AAAB/wAAfP4AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAARP4AAAD/AAAA+wAAAB////8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AAAAAAMAAADCAAAA/wAAAv8AAIb+AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADD/QAAAP8AAAD/AAAAYf///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
AAAAgQAAAP8AAAD/AAB2/gAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AAAf/wAAAP8AAACa////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAAEAA
AAD9AAAA/wAAPv4AANj9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAE7+AAAA/wAAANL///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wAAAAAFAAAA4QAA
AP8AABf/AADI/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA1P0AALX9AACj/QAAlf4AAIb+AAB0/gAAYP4A
AFn+AABK/gAAOP4AACn/AAAb/wAADv8AAAr/AAAQ/wAAFv8AAB7/AAAl/wAALP8AADX/AAA+/gAA
R/4AAFL+AABb/gAAY/4AAHr+AACc/gAAvv0AANj9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAbv4AAAD/AAAA9P///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAAFgAAAD/AAAA
/wAAmv4AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAAwv0AAIr+AQFU/ggILv4MDBf/EBAR/xISEv8UFBX/FhYY/xkZG/8dHR//IiIj/wkJ
Cf8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA
/wAAAP8AAAH/AAAE/wAACP8AAAX/AAAA/wAABf8AAB//AABG/gAAa/4AAIz+AACv/QAA0P0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AABM/gAAAP8AAADN////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAwwAAAP8AACP/
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAyf0AAH/+BQU//gwM
H/8SEhX/GBgY/yUlJv84ODv/SEhI/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/GBgY
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/
AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAF/wAABv8AAAD/AAAA/wAAE/8A
AE7+AACO/gAAyf0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AACL/AAAA/wAAAJr///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAAC8AAAD/AAAA/wAAff4A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADQ/QAAf/4FBSf+Dw8P/x4eIP8/P0H/UFBQ
/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9AQED/
BgYG/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAA
Av8AAAb/AAAA/wAAJ/8AAG7+AADB/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADN/QAAAv8AAAD/AAAAZ////wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAjAAAAP8AAAv/AADO/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANT9AACY/gICO/4ODg//IiIk/0RERP9RUVH/UVFR/1FRUf9RUVH/
UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf8N
DQ3/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAA
AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA
/wAAAP8AAAD/AAAA/wAABv8AAAH/AABB/gAAov4AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAGP+AAAA/wAAAP8AAAAs////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wAAAACvAAAA/wAAPv4AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AAM79AABg/gAACf8JCQv/JSUm/1BQUP9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9R
UVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/xYW
Fv8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/
AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAL/AAAC/wAAHf8AAJb+AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AACy/QAAA/8AAAD/AAAAqP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAAMgAAAD/AABS/gAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AACU/gAAEf8BAQb/EhIS/0ZGRv9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FR
Uf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/FhYW
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/
AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAv8AAD3+AAC//QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2P0AADH/AAAA/wAAAPEAAAAZ////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAA4QAAAP8AAGb+AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
Xv4AAAT/AAAA/wsLC/9MTEz/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR
/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf8RERH/
AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAA
AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAABf8AAAX/AAB+/gAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AAB1/gAAAP8AAAD/AAAAbP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wAAAADxAAAA/wAAb/4AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAHj+AAAD
/wAAAP8AAAD/GBgY/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/
UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/Nzc3/wcHB/8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAA
AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAP/AABv/gAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAAdv4AAAD/AAAA/wAAAMoAAAAC////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AAAAAMUAAAD/AABE/gAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADF/QAAAP8AAAD/
AAAA/wAAAP8qKir/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9R
UVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/z8/P/8KCgr/AAAA/wAA
AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/
AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAP/AABs/gAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AAG7+AAAA/wAAAP8AAADYAAAAG////wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAiQAAAP8AABP/AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AALP9AAAA/wAAAP8A
AAD/AAAA/y8vL/9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FR
Uf9RUVH/UVFR/1FRUf9RUVH/S0tL/z09Pf8pKSn/GRkZ/xISEv8MDAz/BgYG/wAAAP8AAAb/AAAH
/wAABv8AAAH/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAE/wAABf8AAAf/AAAI/wAACP8AAAf/
AAAF/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAL/AACk/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AABm
/gAAAP8AAAD/AAAA0wAAABf///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wAAAABNAAAA/wAAAP8AALf9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAo/0AAAT/AAAA/wAA
AP8AAAD/HBwc/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/1FRUf9QUFD/QUFB
/y4uLv8cHBz/FBQU/w4OD/8JCQz/AgIC/wAAAP8AAAr/AAAb/wAAL/8AAEb+AABe/gAAcP4AAIT+
AACX/gAAqv0AAL39AADO/QAAyv0AAMH9AAC3/QAArv0AAKT9AACb/gAAkf4AAIj+AAB//gAAdf4A
AGr+AABH/gAAH/8AAAP/AAAA/wAABf8AAAb/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAA
AP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAABv8AAHD+AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADR/QAAVP4AAAD/
AAAA/wAAAM0AAAAT////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AAAAABIAAAD6AAAA/wAAS/4AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AACm/QAAA/8AAAD/AAAA
/wAAAP8MDAz/T09P/1FRUf9RUVH/UVFR/1FRUf9RUVH/UVFR/0JCQv8mJib/FRUV/w0NDf8FBQn/
AAAA/wAABP8AACj/AABa/gAAh/4AALT9AADW/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA1v0AALn9AACV/gAAcP4AAEn+AAAg/wAABP8AAAD/AAAH/wAAAP8AAAD/AAAA
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAOf4AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAqP0AAB//AAAA/wAAAP8A
AADHAAAAD////wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AAAAAIkAAAD/AAAA/wAAnf4AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAL39AAAA/wAAAP8AAAD/
AAAA/wICAv8yMjL/UVFR/1FRUf9OTk7/MTEx/xUVFf8NDQ3/BQUF/wAABP8AAAH/AAAr/wAAc/4A
AK/9AADV/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADX/QAAtf0AAHb+AAAw/wAAAf8AAAb/
AAAC/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAK/wAA2P0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA1P0AAGb+AAAD/wAAAP8AAAD/AAAApgAA
AAz///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8AAAAACgAAAOAAAAD/AAAd/wAA0f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA0/0AAAD/AAAA/wAAAP8A
AAD/AAAA/xMTE/87Ozv/GBgY/wsLC/8BAQH/AAAF/wAABf8AAEj+AACN/gAAyv0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADM/QAAj/4A
AEv+AAAL/wAAAv8AAAX/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAC8/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AALH9AAAn/wAAAP8AAAD/AAAA6wAAAFT///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAATQAAAP8AAAD/AABJ/gAA1v0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAGP8AAAD/AAAA/wAA
AP8AAAD/BQUF/wMDA/8AAAL/AAAB/wAAH/8AAH7+AADM/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANf9AACn/QAAXP4AAAT/AAAF/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAK/9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANT9AABx/gAABf8AAAD/AAAA/wAAALAAAAAX////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAqAAAAP8AAAD/AABD/gAA
0/0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AABN/gAAAf8AAAD/AAAA
/wAAAP8AAAX/AAAD/wAASv4AAKb9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAAwv0AAFf+AAAC/wAABf8AAAD/AAAA/wAAAP8AAAD/AAAC/wAAqP0AANn9
AADZ/QAA2f0AANb9AACF/gAAGf8AAAD/AAAA/wAAAPAAAABe////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wAAAAAGAAAArgAAAP8AAAD/AAA7
/gAA0f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAID+AAAI/wAAAP8AAAP/
AAAB/wAAS/4AAL/9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AAL79AABO/gAAAf8AAAT/AAAA/wAAAP8AAAX/AACf/gAA2f0A
ANj9AACP/gAAIf8AAAD/AAAA/wAAAP8AAAC4AAAAHP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wAAAAADAAAAoQAAAP8AAAD/
AAAz/wAAwP0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAr/0AAAD/AAAD/wAANf8A
ALD9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AAC4/QAAH/8AAAX/AAAA/wAAAP8AALf9AACZ/gAA
KP8AAAD/AAAA/wAAAP8AAADKAAAARf///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wAAAAABAAAAlAAAAP8A
AAD/AAAK/wAAef4AANf9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADV/QAAL/8AAJ7+AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADL/QAAI/8AAAD/AAAd/wAAMf8AAAD/AAAA
/wAAAP8AAADUAAAAUf///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAeQAA
APkAAAD/AAAA/wAALv8AALH9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AACo/QAAAP8AAAD/AAAA/wAAAP8AAADd
AAAAXQAAAAL///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAA
KQAAAMMAAAD/AAAA/wAAA/8AAGb+AADQ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QQE2f0JCdr9Cwva/QwM2v0ODtv9Dw/b/QwM
2v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAMr9AAAB/wAAAP8AAADlAAAAaAAAAAX/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
AAAAAQAAAGUAAADuAAAA/wAAAP8AAA7/AABj/gAAwf0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9BATZ/R4e3f08POH9VFTl/lVV5f5VVeX+VVXl/lRU5f5UVOX+VFTl
/k5O5P47O+H9Jyfe/QoK2v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAfv4AAAD/AAAA/wAAACT///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AAAAABcAAACmAAAA/wAAAP8AAAD/AAAD/wAASf4AAKf9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9ExPb/Tc34f1QUOT+U1Pl/lJS5f5SUuX+UlLl/lJS5f5RUeX+UVHl/lFR5f5QUOT+
UFDk/lBQ5P5QUOT+Tk7k/jk54f0bG939AQHZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AAAv/wAAAP8AAADF////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wAAAAAxAAAAoAAAAPkAAAD/AAAA/wAAAP8AAC3/AACM/gAA1v0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AwPZ/Sws3/1PT+T+UFDk/k9P5P5PT+T+T0/k/k9P5P5OTuT+Tk7k/k5O5P5OTuT+TU3k/k1N5P5N
TeT+TU3k/kxM5P5MTOT+TEzk/kxM5P4/P+L9Fxfc/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAAuf0AAAD/AAAA/wAAAGj///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8AAAAAFwAAAIAAAADpAAAA/wAAAP8AAAD/AABn/gAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/RAQ2/1B
QeL+TU3k/k1N5P5MTOT+TEzk/kxM5P5LS+T+S0vk/ktL5P5LS+T+Skrk/kpK5P5KSuT+Skrk/klJ
4/5JSeP+SUnj/klJ4/5ISOP+SEjj/khI4/5ISOP+NTXg/Q4O2/0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AABp/gAAAP8AAAD4AAAAEf///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AAAAAAcAAABgAAAA2QAAAP8AAB3/AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0hId39SUnj/kpK
5P5JSeP+SUnj/klJ4/5JSeP+SEjj/khI4/5ISOP+SEjj/kdH4/5HR+P+R0fj/kZG4/5GRuP+Rkbj
/kZG4/5FReP+RUXj/kVF4/5FReP+RETj/kRE4/5EROP+Q0Pj/iEh3f0BAdn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2P0AABv/AAAA/wAAAKz///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wAAAABpAAAA/wAAA/8AANb9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9Hx/d/UdH4/5GRuP+Rkbj
/kZG4/5GRuP+RUXj/kVF4/5FReP+RUXj/kRE4/5EROP+RETj/kRE4/5DQ+P+Q0Pj/kND4/5CQuL+
QkLi/kJC4v5CQuL+QUHi/kFB4v5BQeL+QUHi/kBA4v5AQOL+QEDi/jIy4P0JCdr9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AACk/QAAAP8AAAD/AAAATv///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AAAAAEcAAAD/AAAA/wAAvf0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/Rwc3f1DQ+P+Q0Pj/kND4/5DQ+P+
QkLi/kJC4v5CQuL+QkLi/kFB4v5BQeL+QUHi/kFB4v5AQOL+QEDi/kBA4v49PeL9NDTg/Ssr3/0i
It79HR3d/R0d3f0dHd39HBzd/Rwc3f0cHN39HBzd/Rsb3f0bG939Gxvd/RgY3P0BAdn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AAFP+AAAA/wAAAOsAAAAF////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAJgAAAP8AAAD/AACg/gAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0ZGdz9QEDi/kBA4v5AQOL+QEDi/j8/4v0/
P+L9Pz/i/T4+4v0+PuL9Pj7i/Tg44f0nJ979Hx/d/RYW3P0ODtv9BQXZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADQ/QAADP8AAAD/AAAAkv///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wAAAAAHAAAA/QAAAP8AAIX+AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9Cwva/Tw84f09PeL9PT3i/Tw84f08POH9PDzh/Tw8
4f07O+H9NTXg/SIi3v0ODtv9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AAHn+AAAA/wAAAP8AAAAx////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wAAAADjAAAA/wAAZ/4AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QIC2f0wMOD9Ojrh/Tk54f05OeH9OTnh/Tk54f0xMeD9Hx/d
/Q0N2v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADV/QAAGP8AAAD/AAAAvf///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AAAAAMIAAAD/AABL/gAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9Hh7d/Tc34f02NuH9Njbh/TY24f0lJd79DAza/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AAIn+AAAA/wAAAP8AAABG////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAoQAAAP8AAC7/AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QsL2v0zM+D9MzPg/TMz4P0lJd79Cwva/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADY/QAAJP8AAAD/AAAAzv///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wAAAAB/AAAA/wAAE/8AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9IyPe/TAw4P0kJN79Cwva/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
AJf+AAAA/wAAAP8AAABX////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AAAAAF4AAAD/AAAA/wAA0P0AANn9AADZ/QAA
2f0AANn9AADZ/QsL2v0jI979Cwva/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADQ/QAAxP0AALj9AACt/QAAr/0AALn9AADM/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
Mv8AAAD/AAAA3QAAAAP///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8AAAAAPQAAAP8AAAD/AACz/QAA2f0AANn9AADZ
/QAA2f0AANn9BATZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA0f0AAMX9AAC5/QAArf0AAKH+AACU/gAAiP4AAID+AACA/gAAgP4AAIL+AADB/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAKP9AAAA
/wAAAP8AAABp////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wAAAAAbAAAA/wAAAP8AAJb+AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANL9AADG/QAA
uv0AAK79AACi/gAAlv4AAIn+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAJ/+AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADW/QAAKP8AAAD/
AAAA6AAAAAj///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AAAAAAEAAAD4AAAA/wAAef4AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADT/QAAx/0AALv9AACv/QAAo/0AAJf+AACK
/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACJ/gAAwv0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAHv+AAAA/wAAAP8A
AABg////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AAAAANkAAAD/AABX/gAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA1P0AAMf9AAC7/QAAr/0AAKP9AACX/gAAjP4AAID+AACA/gAAgP4AAID+
AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAnP4AANL9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADF/QAADf8AAAD/AAAAwwAA
AAH///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8AAAAApgAAAP8AACb/AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANX9
AADJ/QAAvP0AALD9AACk/QAAmP4AAIz+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4A
AID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAnP4AAMX9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAE3+AAAA/wAAAPsAAAAt////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wAAAABrAAAA/wAAAv8AAM39AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADW/QAAyv0AAL39AACx/QAApf0A
AJn+AACN/gAAgf4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAA
gP4AAID+AACA/gAAgP4AAID+AACD/gAApP0AAMz9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AACj/QAAAP8AAAD/AAAAjv///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AAAAADEAAAD/AAAA/wAAnv4AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA1/0AAMv9AAC//QAAsv0AAKb9AACa/gAAjv4AAIL+AACA/gAA
gP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA
/gAAgP4AAIn+AACj/QAAv/0AANb9AADZ/QAA2f0AANn9AQHZ/Q4O2/0WFtz9HR3d/SUl3v0sLN/9
ICDd/Q8P2/0AANn9AADZ/QAA2f0AANn9AADZ/QAAy/0AAB7/AAAA/wAAAOUAAAAN////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8AAAAAAwAAAPMAAAD/AABi/gAA2f0AANn9AADZ/QAA
2f0AANn9AADR/QAAwP0AALP9AACn/QAAm/4AAI/+AACD/gAAgP4AAID+AACA/gAAgP4AAID+AACA
/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAkf4AAK39
AADH/QAA2f0AANn9AQHZ/Q4O2/0eHt39Li7f/T4+4v1NTeT+UlLl/lNT5f5UVOX+Vlbl/ldX5v5Y
WOb+Wlrm/khI4/4aGtz9AADZ/QAA2f0AANb9AAA7/gAAAP8AAAD/AAAAVf///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8AAAAApwAAAP8AABb/AADW/QAA2f0AANn9AADZ
/QAAx/0AAJz+AACQ/gAAhP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+
AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAIP+AACa/gAAtf0AAM/9AgLZ/Q4O2/0c
HN39Kyvf/To64f1ISOP+SEjj/j094v0xMeD9JCTe/Roa3P0aGtz9Ghrc/Roa3P0bG939Gxvd/Sgo
3/1JSeP+W1vm/lxc5v4SEtv9AADZ/QAAY/4AAAD/AAAA/wAAAI////8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wAAAABJAAAA/wAAAP8AAJz+AADZ/QAA2f0AANn9
AADP/QAAqf0AAIX+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4AAID+AACA/gAAgP4A
AID+AACA/gAAgP4AAID+AACJ/gAAmf4AAKn9AAC9/QEB1f0ODtv9ICDd/TIy4P0/P+L9Nzfh/Sws
3/0hId39FRXc/QoK2v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0QENv9EBDb/QAA2f0AAI3+AAAA/wAAAP8AAAC7AAAAA////wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AAAAAAMAAADnAAAA/wAAQf4AANn9AADZ/QAA2f0A
ANn9AADZ/QAA1P0AALH9AACg/gAAl/4AAI/+AACH/gAAgP4AAIL+AACJ/gAAkP4AAJf+AACe/gAA
pf0AALP9AADD/QAA0v0AANn9CAja/RgY3P0qKt/9MzPg/Sgo3/0ZGdz9Cgra/QEB2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AACm/QAACP8AAAD/AAAA3AAAABH///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AAAAAIQAAAD/AAAA/wAAjv4AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADY/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QQE2f0SEtv9ISHd/Soq3/0jI979Fhbc/QcH2v0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAAkf4AAAf/AAAA/wAAAPIAAAAq////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8AAAAACQAAANcAAAD/AAAP/wAAgP4AAMz9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9BgbZ/RYW3P0fH939
Hx/d/RIS2/0FBdn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AAHb+AAAB/wAAAP8AAADuAAAAPf///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8AAAAAMwAAAPoAAAD/AAAA/wAAAP8AAAr/
AAAc/wAALf8AAD7+AABP/gAAYP4AAHH+AACE/gAAqf0FBdL9DAza/RAQ2/0PD9v9BATZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AAM39AABV
/gAAAP8AAAD/AAAA3wAAACj///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8AAAAARwAAAMQAAAD/AAAA/wAAAP8A
AAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AwMD/wICBf8AACr/AABY/gAAhf4AALP9AADW/QAA
2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ
/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANj9AACH/gAAE/8AAAD/
AAAA/wAAAMsAAAAX////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAACYAAABlAAAAegAA
AI4AAACiAAAAtgAAAMoAAADeAAAA8gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAn/AAA0
/wAAYf4AAI3+AAC5/QAA2P0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9
AADZ/QAA2f0AANn9AADZ/QAA2f0AANn9AADZ/QAA2f0AANj9AACi/gAALv8AAAD/AAAA/wAAAP8A
AACmAAAACv///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8AAAAACgAAADoAAABvAAAApQAAANoAAAD+AAAA/wAAAP8AAAD/
AAAA/wAAAP8AAAD/AAAM/wAANv4AAGL+AACO/gAAuv0AANj9AADZ/QAA2f0AANn9AADZ/QAA2f0A
ANn9AADZ/QAA2f0AANn9AADZ/QAA1v0AAKz9AABh/gAAGP8AAAD/AAAA/wAAAP8AAADTAAAAQf//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AAAAABEAAABFAAAAewAAALAA
AADlAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAACf8AABn/AAAl/wAAMv8AAD7+AABK/gAA
Vv4AAGP+AABj/gAAQ/4AACL/AAAE/wAAAP8AAAD/AAAA/wAAAP8AAADrAAAAbQAAAAP///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wAAAAAZAAAATQAAAIEAAAC2AAAA6gAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA
/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAPAAAACgAAAASQAAAAX///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8AAAAAHgAAAFIAAAB0AAAAggAAAJEAAACgAAAArwAAAL0AAADM
AAAA2wAAAN8AAAC8AAAAlQAAAG8AAABEAAAABv///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD/
//8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP//
/wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////
AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A
////AP///wD///8A////AP///wD///8A////AP///wD///8A////AP///wD///8A////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////+AA
AAD///////////////gAAAAAAf////////////+AAAAAAAAH///////////4AAAAAAAAAH//////
////wAAAAAAAAAAP/////////gAAAAAAAAAAAf////////gAAAAAAAAAAAA////////gAAAAAAAA
AAAAD///////gAAAAAAAAAAAAAP//////gAAAAAAAAAAAAAA//////gAAAAAAAAAAAAAAD/////g
AAAAAAAAAAAAAAAf////wAAAAAAAAAAAAAAAD////4AAAAAAAAAAAAAAAAf///4AAAAAAAAAAAAA
AAAD///8AAAAAAAAAAAAAAAAAf//+AAAAAAAAAAAAAAAAAD///AAAAAAAAAAAAAAAAAA///gAAAA
AAAAAAAAAAAAAH//wAAAAAAAAAAAAAAAAAB//8AAAAAAAAAAAAAAAAAAf/+AAAAAAAAAAAAAAAAA
AH//AAAAAAAAAAAAAAAAAAB//wAAAAAAAAAAAAAAAAAAf/8AAAAAAAAAAAAAAAAAAH/+AAAAAAAA
AAAAAAAAAAB//gAAAAAAAAAAAAAAAAAAf/4AAAAAAAAAAAAAAAAAAP/+AAAAAAAAAAAAAAAAAAD/
/gAAAAAAAAAAAAAAAAAB//4AAAAAAAAAAAAAAAAAAf/+AAAAAAAAAAAAAAAAAAP//gAAAAAAAAAA
AAAAAAAH//4AAAAAAAAAAAAAAAAAD//+AAAAAAAAAAAAAAAAAB///wAAAAAAAAAAAAAAAAA///8A
AAAAAAAAAAAAAAAA////gAAAAAAAAAAAAAAAAf///8AAAAAAAAAAAAAAAAf////AAAAAAAAAAAAA
AAAP////4AAAAAAAAAAAAAAAP/////AAAAAAAAAAAAAAAP/////8AAAAAAAAAAAAAAH//////gAA
AAAAAAAAAAAH//////8AAAAAAAAAAAAAH///////wAAAAAAAAAAAAD////////AAAAAAAAAAAAA/
///////8AAAAAAAAAAAAP////////wAAAAAAAAAAAH/////////AAAAAAAAAAAB/////////wAAA
AAAAAAAAf////////8AAAAAAAAAAAP/////////AAAAAAAAAAAD/////////4AAAAAAAAAAB////
/////+AAAAAAAAAAAf/////////gAAAAAAAAAAP/////////4AAAAAAAAAAD/////////+AAAAAA
AAAAA//////////gAAAAAAAAAAf/////////4AAAAAAAAAAH/////////+AAAAAAAAAAD///////
///wAAAAAAAAAA//////////8AAAAAAAAAAf//////////AAAAAAAAAAP//////////wAAAAAAAA
AD//////////8AAAAAAAAAB///////////gAAAAAAAAA///////////4AAAAAAAAAP//////////
+AAAAAAAAAH///////////wAAAAAAAAD///////////8AAAAAAAAB////////////gAAAAAAAA//
//////////8AAAAAAAAf////////////wAAAAAAAP//////////////gAAAAAP//////////////
/wAAAAH////////////////4AAAH/////////////////8AAP///////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////8=
"""
import socket as sock
import re

class IPAdress():
    def __init__(self):
        self.osint_options = {
            "reverse lookup": self.reverse_lookup,
            "ip to asn": self.ip_to_asn,
            "ipv4 CIDR report": self.reverse_lookup
        }

    def is_ip_address(self, _input: str):
        try:
            sock.inet_aton(_input)
            return True
        except sock.error:
            return False

    def reverse_lookup(self, ip):
        return sock.gethostbyaddr(ip)[0]
    
    def ip_to_asn(self):
        pass

class EmailAddress():
    def __init__(self):
        self.osint_options = {
            "haveibeenpwnd": self.hibp_lookup,
            "extract domain": self.domain_extract
        }

    def is_valid_email(self, _input: str):
        if re.match('^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$', _input):
            return True
        return False
    
    def hibp_lookup(self):
        pass

    def domain_extract(self, email):
        return email.split("@")[1]

class InputValidator():
    def __init__(self):
        self.ip = IPAdress()
        self.email = EmailAddress()

    def run(self, _function, **kwargs):
        try:
            return _function(**kwargs)
        except Exception as e:
            return e

    def validate(self, _input):
        if self.ip.is_ip_address(_input):
            return [True, "input: ipv4 address", [option for option in self.ip.osint_options.keys()]]
        elif self.email.is_valid_email(_input):
            return [True, "input: email address", [option for option in self.email.osint_options.keys()]]
        return [False, []]

    def execute_transform(self, _input: str, transform: str):
        if self.ip.is_ip_address(_input):
            return self.run(self.ip.osint_options.get(transform), ip=_input)
        elif self.email.is_valid_email(_input):
            return self.run(self.email.osint_options.get(transform), email=_input)
import unittest
from utils import InputValidator

class TestValidator(unittest.TestCase):
    def setUp(self):
        self.validator = InputValidator()

    def test_ip_validation(self):
        output = self.validator.validate("192.168.1.1")
        self.assertTrue(output[0][0])
        self.assertEqual(output[0][1], "input: ipv4 address")

    def test_email_validation(self):
        output = self.validator.validate("test@test.com")
        self.assertTrue(output[0][0])
        self.assertEqual(output[0][1], "input: email address")

    def test_domain_validation(self):
        output = self.validator.validate("google.com")
        self.assertTrue(output[0][0])
        self.assertEqual(output[0][1], "input: domain")

    def test_url_validation(self):
        output = self.validator.validate("https://www.google.com")
        self.assertTrue(output[0][0])
        self.assertEqual(output[0][1], "input: url")

    def test_md5_validation(self):
        output = self.validator.validate("05f3044a84e6149e80af2c787433c375")
        self.assertTrue(output[0][0])
        self.assertEqual(output[0][1], "input: md5")

    def test_sha256_validation(self):
        output = self.validator.validate("20296EF7D8F8DE38540AE282A50E1B38CA65ABBF201561741847CEABE4BB7801")
        self.assertTrue(output[0][0])
        self.assertEqual(output[0][1], "input: sha256")

    def test_validation_failure(self):
        output = self.validator.validate("diwheih}£££")
        self.assertFalse(output[0][0])

    def test_consistency_check(self):
        test_list = ["ip"]
        output_1 = self.validator.consistency_check(test_list, "ip")
        output_2 = self.validator.consistency_check(test_list, "email")
        self.assertTrue(output_1)
        self.assertFalse(output_2)

    def test_transform_execution(self):
        output = self.validator.execute_transform("8.8.8.8", "dns: reverse lookup")
        self.assertEqual(output[0], "dns.google")

if __name__ == '__main__':
    unittest.main()
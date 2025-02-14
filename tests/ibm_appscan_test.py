import os
import sys
import unittest
from pathlib import Path

from base_test_class import BaseTestCase
from product_test import ProductTest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select

dir_path = str(Path(os.path.realpath(__file__)).parent)


class IBMAppScanTest(BaseTestCase):

    def test_import_ibm_app_scan_result(self):
        # Login to the site.
        # Username and password will be gotten from environ
        driver = self.driver
        # Navigate to the Endpoint page
        self.goto_product_overview(driver)
        # wait for product_wrapper div as datatables javascript modifies the DOM on page load.
        driver.find_element(By.ID, "products_wrapper")
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the Finding Drop down
        driver.find_element(By.PARTIAL_LINK_TEXT, "Findings").click()
        # "Click" the New Endpoint
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        # Select scan type
        Select(driver.find_element(By.ID, "id_scan_type")).select_by_visible_text("IBM AppScan DAST")
        # Select `Default` as the Environment
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        # Upload Scan result file
        scanner_file = dir_path / "ibm_appscan_xml_file.xml"
        driver.find_element(By.NAME, "file").send_keys(str(scanner_file))
        # click on upload button
        driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()
        # Query the site to determine if the finding has been added

        # Assert the query to determine status or failure
        self.assertTrue(self.is_success_message_present(text="IBM AppScan DAST processed a total of 27 findings"))


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(BaseTestCase("disable_block_execution"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(IBMAppScanTest("test_import_ibm_app_scan_result"))
    suite.addTest(ProductTest("test_delete_product"))
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)

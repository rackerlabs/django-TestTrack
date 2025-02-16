import logging
import os
import sys
import unittest
from pathlib import Path

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

logger = logging.getLogger(__name__)


class CloseOldTest(BaseTestCase):
    # --------------------------------------------------------------------------------------------------------
    # This set of tests is similar to close_old_findings_dedupe_test.py, but does not rely on deduplication
    # Testing that two different scans of the same type will properly close the old findings on the second import.
    # --------------------------------------------------------------------------------------------------------
    def setUp(self):
        super().setUp()
        self.relative_path = Path(os.path.realpath(__file__)).parent

    @on_exception_html_source_logger
    def test_delete_findings(self):
        logger.debug("removing previous findings...")
        driver = self.driver
        driver.get(self.base_url + "finding?page=1")

        if self.element_exists_by_id("no_findings"):
            text = driver.find_element(By.ID, "no_findings").text
            if "No findings found." in text:
                return

        driver.find_element(By.ID, "select_all").click()
        driver.find_element(By.CSS_SELECTOR, "i.fa-solid.fa-trash").click()
        try:
            WebDriverWait(driver, 1).until(EC.alert_is_present(),
                "Timed out waiting for finding delete confirmation popup to appear.")
            driver.switch_to.alert.accept()
        except TimeoutException:
            self.fail("Confirmation dialogue not shown, cannot delete previous findings")

        logger.debug("page source when checking for no_findings element")
        logger.debug(self.driver.page_source)
        text = driver.find_element(By.ID, "no_findings").text

        self.assertIsNotNone(text)
        self.assertIn("No findings found.", text)
        # check that user was redirect back to url where it came from based on return_url
        self.assertTrue(driver.current_url.endswith("page=1"), driver.current_url)

# --------------------------------------------------------------------------------------------------------
# Same scanner import - Close Old Findings on engagement
# --------------------------------------------------------------------------------------------------------
    @on_exception_html_source_logger
    def test_add_same_engagement_engagement(self):
        logger.debug("Same scanner deduplication - Close Old Findings No Dedupe, Same Engagement - dynamic. Creating tests...")
        # Create engagement

        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Close Same Engagement No Dedupe")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()

        self.assertTrue(self.is_success_message_present(text="Engagement added successfully."))

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on engagement
#   Test deduplication for Immuniweb dynamic scanner
#   Tests importing findings from the same scanner, first test is the same report twice.
#   Second test contains only one of the original findings.
#   Uses the import feature
# --------------------------------------------------------------------------------------------------------
    @on_exception_html_source_logger
    def test_import_same_engagement_tests(self):
        logger.debug("Importing reports...")
        # Imports into
        # First test : Immuniweb Scan (dynamic)

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Close Same Engagement No Dedupe").click()
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        scan_type = Select(driver.find_element(By.ID, "id_scan_type"))
        scan_type.select_by_visible_text("Immuniweb Scan")

        scan_environment = Select(driver.find_element(By.ID, "id_environment"))
        scan_environment.select_by_visible_text("Development")
        driver.find_element(By.ID, "id_close_old_findings").click()
        driver.find_element(By.ID, "id_file").send_keys(self.relative_path / "close_old_scans/closeold_nodedupe_1.xml")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text="3 findings and closed 0 findings"))

        # Second upload. Immuniweb again.
        # Same report.
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Close Same Engagement No Dedupe").click()
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        scan_type = Select(driver.find_element(By.ID, "id_scan_type"))
        scan_type.select_by_visible_text("Immuniweb Scan")

        scan_environment = Select(driver.find_element(By.ID, "id_environment"))
        scan_environment.select_by_visible_text("Development")
        driver.find_element(By.ID, "id_close_old_findings").click()
        driver.find_element(By.ID, "id_file").send_keys(self.relative_path / "close_old_scans/closeold_nodedupe_2.xml")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text="3 findings and closed 3 findings"))

    @on_exception_html_source_logger
    def test_close_same_engagement_tests(self):
        logger.debug("Importing reports...")
        # Second test : Immuniweb Scan (dynamic)
        # Should be run after test_import_same_engagement_tests()

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Close Same Engagement No Dedupe").click()
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        scan_type = Select(driver.find_element(By.ID, "id_scan_type"))
        scan_type.select_by_visible_text("Immuniweb Scan")

        scan_environment = Select(driver.find_element(By.ID, "id_environment"))
        scan_environment.select_by_visible_text("Development")
        driver.find_element(By.ID, "id_close_old_findings").click()
        driver.find_element(By.ID, "id_file").send_keys(self.relative_path / "dedupe_scans/dedupe_and_close_1.xml")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text="1 findings and closed 3 findings"))

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on product
#   Test deduplication for Immuniweb dynamic scanner
# --------------------------------------------------------------------------------------------------------

    @on_exception_html_source_logger
    def test_add_same_product_engagement(self):
        logger.debug("Same scanner no deduplication - Close Old Findings Same Product - dynamic. Creating tests...")
        # Create engagement

        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Close Same Product No Dedupe Test 1")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()

        self.assertTrue(self.is_success_message_present(text="Engagement added successfully."))

        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Close Same Product No Dedupe Test 2")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()

        self.assertTrue(self.is_success_message_present(text="Engagement added successfully."))

        self.goto_product_overview(driver)
        driver.find_element(By.CSS_SELECTOR, ".dropdown-toggle.pull-left").click()
        driver.find_element(By.LINK_TEXT, "Add New Engagement").click()
        driver.find_element(By.ID, "id_name").send_keys("Close Same Product No Dedupe Test 3")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()

        self.assertTrue(self.is_success_message_present(text="Engagement added successfully."))

# --------------------------------------------------------------------------------------------------------
# Same scanner deduplication - Deduplication on product
#   Test deduplication for Immuniweb dynamic scanner
#   Tests importing findings from the same scanner, first test is the same report twice.
#   Second test contains only one of the original findings.
#   Uses the import feature
# --------------------------------------------------------------------------------------------------------

    @on_exception_html_source_logger
    def test_import_same_product_tests(self):
        logger.debug("Importing reports...")
        # First test : Immuniweb Scan (dynamic)

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Close Same Product No Dedupe Test 1").click()
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        scan_type = Select(driver.find_element(By.ID, "id_scan_type"))
        scan_type.select_by_visible_text("Immuniweb Scan")

        scan_environment = Select(driver.find_element(By.ID, "id_environment"))
        scan_environment.select_by_visible_text("Development")
        driver.find_element(By.ID, "id_close_old_findings_product_scope").click()
        driver.find_element(By.ID, "id_file").send_keys(self.relative_path / "close_old_scans/closeold_nodedupe_1.xml")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text="3 findings and closed 0 findings"))

        # Second upload. Immuniweb again.
        # Same report.
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Close Same Product No Dedupe Test 2").click()
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        scan_type = Select(driver.find_element(By.ID, "id_scan_type"))
        scan_type.select_by_visible_text("Immuniweb Scan")

        scan_environment = Select(driver.find_element(By.ID, "id_environment"))
        scan_environment.select_by_visible_text("Development")
        driver.find_element(By.ID, "id_close_old_findings_product_scope").click()
        driver.find_element(By.ID, "id_file").send_keys(self.relative_path / "close_old_scans/closeold_nodedupe_2.xml")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text="3 findings and closed 3 findings"))

    @on_exception_html_source_logger
    def test_close_same_product_tests(self):
        logger.debug("Importing reports...")
        # Second test : Immuniweb Scan (dynamic)
        # Should be run after test_import_same_engagement_tests()

        driver = self.driver
        self.goto_active_engagements_overview(driver)
        driver.find_element(By.PARTIAL_LINK_TEXT, "Close Same Product No Dedupe Test 3").click()
        driver.find_elements(By.CLASS_NAME, "btn-primary")[3].click()
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        scan_type = Select(driver.find_element(By.ID, "id_scan_type"))
        scan_type.select_by_visible_text("Immuniweb Scan")

        scan_environment = Select(driver.find_element(By.ID, "id_environment"))
        scan_environment.select_by_visible_text("Development")
        driver.find_element(By.ID, "id_close_old_findings_product_scope").click()
        driver.find_element(By.ID, "id_file").send_keys(self.relative_path / "dedupe_scans/dedupe_and_close_1.xml")
        driver.find_elements(By.CLASS_NAME, "btn-primary")[1].click()

        self.assertTrue(self.is_success_message_present(text="1 findings and closed 3 findings"))


def add_close_old_tests_to_suite(suite, *, jira=False, github=False, block_execution=False):
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=jira, github=github, block_execution=block_execution)

    if jira:
        suite.addTest(BaseTestCase("enable_jira"))
    else:
        suite.addTest(BaseTestCase("disable_jira"))
    if github:
        suite.addTest(BaseTestCase("enable_github"))
    else:
        suite.addTest(BaseTestCase("disable_github"))
    if block_execution:
        suite.addTest(BaseTestCase("enable_block_execution"))
    else:
        suite.addTest(BaseTestCase("disable_block_execution"))

    suite.addTest(ProductTest("test_create_product"))
    # Test same scanners - same engagement - dynamic - dedupe
    suite.addTest(CloseOldTest("test_delete_findings"))
    suite.addTest(CloseOldTest("test_add_same_engagement_engagement"))
    suite.addTest(CloseOldTest("test_import_same_engagement_tests"))
    suite.addTest(CloseOldTest("test_close_same_engagement_tests"))
    # Test same scanners - same product - dynamic - dedupe
    suite.addTest(CloseOldTest("test_delete_findings"))
    suite.addTest(CloseOldTest("test_add_same_product_engagement"))
    suite.addTest(CloseOldTest("test_import_same_product_tests"))
    suite.addTest(CloseOldTest("test_close_same_product_tests"))
    # Clean up
    suite.addTest(ProductTest("test_delete_product"))
    return suite


def suite():
    suite = unittest.TestSuite()
    add_close_old_tests_to_suite(suite, jira=False, github=False, block_execution=False)
    add_close_old_tests_to_suite(suite, jira=True, github=True, block_execution=True)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)

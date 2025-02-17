import logging
import os
import sys
import time
import unittest
from pathlib import Path

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from product_test import ProductTest, WaitForPageLoad
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait
from user_test import UserTest

logger = logging.getLogger(__name__)
dir_path = str(Path(os.path.realpath(__file__)).parent)


class FindingTest(BaseTestCase):

    def test_list_findings_all(self):
        return self.test_list_findings("finding")

    def test_list_findings_closed(self):
        return self.test_list_findings("finding/closed")

    def test_list_findings_accepted(self):
        return self.test_list_findings("finding/accepted")

    def test_list_findings_open(self):
        return self.test_list_findings("finding/open")

    def test_list_findings(self, suffix):
        # bulk edit dropdown menu
        driver = self.driver
        driver.get(self.base_url + suffix)

        driver.find_element(By.ID, "select_all").click()

        driver.find_element(By.ID, "dropdownMenu2").click()

        bulk_edit_menu = driver.find_element(By.ID, "bulk_edit_menu")
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_active").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_verified").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_false_p").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_out_of_scope").is_enabled(), False)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_is_mitigated").is_enabled(), False)

        driver.find_element(By.ID, "id_bulk_status").click()

        bulk_edit_menu = driver.find_element(By.ID, "bulk_edit_menu")
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_active").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_verified").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_false_p").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_out_of_scope").is_enabled(), True)
        self.assertEqual(bulk_edit_menu.find_element(By.ID, "id_bulk_is_mitigated").is_enabled(), True)

    def test_quick_report(self):
        # bulk edit dropdown menu
        driver = self.driver
        driver.get(self.base_url + "finding")

        driver.find_element(By.ID, "downloadMenu").click()
        driver.find_element(By.ID, "report").click()

        self.assertIn("<title>Finding Report</title>", driver.page_source)

    def check_file(self, file_name):
        file_found = False
        for i in range(1, 30):
            time.sleep(1)
            if Path(file_name).is_file():
                file_found = True
                break
        self.assertTrue(file_found, f"Cannot find {file_name}")
        Path(file_name).unlink()

    def test_csv_export(self):
        driver = self.driver
        driver.get(self.base_url + "finding")

        driver.find_element(By.ID, "downloadMenu").click()
        driver.find_element(By.ID, "csv_export").click()

        time.sleep(10)

        self.check_file(f"{self.export_path}/findings.csv")

    def test_excel_export(self):
        driver = self.driver
        driver.get(self.base_url + "finding")

        driver.find_element(By.ID, "downloadMenu").click()
        driver.find_element(By.ID, "excel_export").click()

        time.sleep(5)

        self.check_file(f"{self.export_path}/findings.xlsx")

    @on_exception_html_source_logger
    def test_edit_finding(self):
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Edit Finding`
        driver.find_element(By.LINK_TEXT, "Edit Finding").click()
        # Change: 'Severity' and 'cvssv3'
        # finding Severity
        Select(driver.find_element(By.ID, "id_severity")).select_by_visible_text("Critical")
        # cvssv3
        driver.find_element(By.ID, "id_cvssv3").send_keys("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        # finding Vulnerability Ids
        driver.find_element(By.ID, "id_vulnerability_ids").send_keys("\nREF-3\nREF-4\n")
        # "Click" the Done button to Edit the finding
        driver.find_element(By.XPATH, "//input[@name='_Finished']").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding saved successfully"))
        self.assertTrue(self.is_text_present_on_page(text="REF-1"))
        self.assertTrue(self.is_text_present_on_page(text="REF-2"))
        self.assertTrue(self.is_text_present_on_page(text="REF-3"))
        self.assertTrue(self.is_text_present_on_page(text="REF-4"))
        self.assertTrue(self.is_text_present_on_page(text="Additional Vulnerability Ids"))

    def test_add_image(self):
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Edit Finding`
        driver.find_element(By.LINK_TEXT, "Manage Files").click()
        # select first file input field: form-0-image
        # Set full image path for image file 'strange.png
        image_path = dir_path / "finding_image.png"
        driver.find_element(By.ID, "id_form-0-file").send_keys(str(image_path))
        driver.find_element(By.ID, "id_form-0-title").send_keys("Image Title")
        # Save uploaded image
        with WaitForPageLoad(driver, timeout=50):
            driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Files updated successfully."))

    @on_exception_html_source_logger
    def test_add_note_to_finding(self):
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()

        # Notes are on the view_test page
        driver.find_element(By.ID, "id_entry").clear()
        driver.find_element(By.ID, "id_entry").send_keys("This is a sample note for all to see.")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.XPATH, "//input[@value='Add Note']").click()

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Note saved."))

    def test_mark_finding_for_review(self):
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Request Peer Reveiw`
        driver.find_element(By.LINK_TEXT, "Request Peer Review").click()
        # select Reviewer
        # Let's make the first user in the list a reviewer
        # set select element style from 'none' to 'inline'
        try:
            WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "id_reviewers")))
        except TimeoutException:
            self.fail("Timed out waiting for reviewer dropdown to initialize ")

        driver.execute_script("document.getElementsByName('reviewers')[0].style.display = 'inline'")
        # select the first option tag
        element = driver.find_element(By.XPATH, "//select[@name='reviewers']")
        reviewer_option = element.find_elements(By.TAG_NAME, "option")[0]
        Select(element).select_by_value(reviewer_option.get_attribute("value"))
        # Add Review notes
        driver.find_element(By.ID, "id_entry").clear()
        driver.find_element(By.ID, "id_entry").send_keys("This is to be reviewed critically. Make sure it is well handled.")
        # Click 'Mark for review'
        driver.find_element(By.NAME, "submit").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding marked for review and reviewers notified."))

    @on_exception_html_source_logger
    def test_clear_review_from_finding(self):
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on `Clear Review` link text
        driver.find_element(By.LINK_TEXT, "Clear Review").click()
        # Mark Active and Verified checkboxes
        driver.find_element(By.ID, "id_active").click()
        driver.find_element(By.ID, "id_verified").click()
        # Add Review notes
        driver.find_element(By.ID, "id_entry").clear()
        driver.find_element(By.ID, "id_entry").send_keys("This has been reviewed and confirmed. A fix needed here.")
        # Click 'Clear reveiw' button
        driver.find_element(By.NAME, "submit").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding review has been updated successfully."))

    def test_delete_image(self):
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Edit Finding`
        driver.find_element(By.LINK_TEXT, "Manage Files").click()
        # mark delete checkbox for first file input field: form-0-DELETE
        driver.find_element(By.ID, "id_form-0-DELETE").click()
        # Save selection(s) for image deletion
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Files updated successfully."))

    def test_close_finding(self):
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        pre_status = driver.find_element(By.XPATH, '//*[@id="vuln_endpoints"]/tbody/tr/td[3]').text
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Close Finding`
        driver.find_element(By.LINK_TEXT, "Close Finding").click()
        # fill notes stating why finding should be closed
        driver.find_element(By.ID, "id_entry").send_keys("All issues in this Finding have been resolved successfully")
        # click 'close Finding' submission button
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added
        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding closed."))
        # Check to see if the endpoint was mitigated
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        # This will throw exception if the test fails due to invalid xpath
        post_status = driver.find_element(By.XPATH, '//*[@id="remd_endpoints"]/tbody/tr/td[3]').text
        # Assert ot the query to dtermine status of failure
        self.assertNotEqual(pre_status, post_status)

    def test_open_finding(self):
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        pre_status = driver.find_element(By.XPATH, '//*[@id="remd_endpoints"]/tbody/tr/td[3]').text
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Open Finding`
        driver.find_element(By.LINK_TEXT, "Open Finding").click()
        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding Reopened."))
        # Check to see if the endpoint was set to active again
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        # This will throw exception if the test fails due to invalid xpath
        post_status = driver.find_element(By.XPATH, '//*[@id="vuln_endpoints"]/tbody/tr/td[3]').text
        # Assert ot the query to dtermine status of failure
        self.assertNotEqual(pre_status, post_status)

    @on_exception_html_source_logger
    def test_simple_accept_finding(self):
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        driver.find_element(By.XPATH, '//*[@id="vuln_endpoints"]/tbody/tr/td[3]').text
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Close Finding`
        driver.find_element(By.LINK_TEXT, "Accept Risk").click()
        # Query the site to determine if the finding has been added
        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding risk accepted."))
        # Check to see if the endpoint was mitigated
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        # This will throw exception if the test fails due to invalid xpath
        # TODO: risk acceptance doesn't mitigate endpoints currently
        # post_status = driver.find_element(By.XPATH, '//*[@id="remd_endpoints"]/tbody/tr/td[3]').text
        # self.assertNotEqual(pre_status, post_status)

    def test_unaccept_finding(self):
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        driver.find_element(By.XPATH, '//*[@id="remd_endpoints"]/tbody/tr/td[3]').text
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Close Finding`
        driver.find_element(By.LINK_TEXT, "Unaccept Risk").click()
        # Query the site to determine if the finding has been added
        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding risk unaccepted."))
        # Check to see if the endpoint was mitigated
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Get the status of the current endpoint
        # This will throw exception if the test fails due to invalid xpath
        # TODO: risk acceptance doesn't mitigate endpoints currently
        # post_status = driver.find_element(By.XPATH, '//*[@id="remd_endpoints"]/tbody/tr/td[3]').text
        # self.assertNotEqual(pre_status, post_status)

    def test_make_finding_a_template(self):
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Make Finding a Template`
        driver.find_element(By.LINK_TEXT, "Make Finding a Template").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding template added successfully. You may edit it here."))

    def test_apply_template_to_a_finding(self):
        driver = self.driver
        # Navigate to All Finding page
        logger.info("\nListing findings \n")
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        self.assertNoConsoleErrors()

        # Click on `Apply Template to Finding`
        driver.find_element(By.LINK_TEXT, "Apply Template to Finding").click()
        self.assertNoConsoleErrors()
        # click on the template of 'App Vulnerable to XSS'
        logger.info("\nClicking on the template \n")
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        self.assertNoConsoleErrors()
        # Click on 'Replace all' button
        logger.info("\nClicking on replace all \n")
        driver.find_element(By.XPATH, "//button[@data-option='Replace']").click()
        self.assertNoConsoleErrors()
        # Click the 'finished' button to submit
        driver.find_element(By.NAME, "_Finished").click()
        self.assertNoConsoleErrors()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_text_present_on_page(text="App Vulnerable to XSS"))

    @on_exception_html_source_logger
    def test_create_finding_from_template(self):
        driver = self.driver
        # Navigate to All Finding page
        # goto engagemnent list (and wait for javascript to load)
        self.goto_all_engagements_overview(driver)

        # Select a previously created engagement title
        driver.find_element(By.PARTIAL_LINK_TEXT, "Ad Hoc Engagement").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Pen Test").click()

        # Click on the 'dropdownMenu1 button'
        # logger.info("\nClicking on dropdown menu \n")
        driver.find_element(By.ID, "dropdownMenu_test_add").click()
        self.assertNoConsoleErrors()

        # Click on `Apply Template to Finding`
        driver.find_element(By.LINK_TEXT, "Finding From Template").click()
        self.assertNoConsoleErrors()
        # click on the template of 'App Vulnerable to XSS'
        logger.info("\nClicking on the template \n")
        driver.find_element(By.LINK_TEXT, "Use This Template").click()
        self.assertNoConsoleErrors()

        driver.find_element(By.ID, "id_title").clear()
        driver.find_element(By.ID, "id_title").send_keys("App Vulnerable to XSS from Template")
        self.assertNoConsoleErrors()
        # Click the 'finished' button to submit
        driver.find_element(By.ID, "id_finished").click()
        self.assertNoConsoleErrors()
        # Query the site to determine if the finding has been added

        # Assert to the query to determine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding from template added successfully."))
        self.assertTrue(self.is_text_present_on_page(text="App Vulnerable to XSS From Template"))

    @on_exception_html_source_logger
    def test_delete_finding_template(self):
        driver = self.driver
        # Navigate to All Finding page
        driver.get(self.base_url + "template")
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on `Delete Template` button
        driver.find_element(By.XPATH, "//button[text()='Delete Template']").click()
        # Click 'Yes' on Alert popup
        driver.switch_to.alert.accept()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Finding Template deleted successfully."))

    def test_import_scan_result(self):
        driver = self.driver
        # Navigate to All Finding page
        self.goto_all_findings_list(driver)
        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'Finding' dropdown menubar
        driver.find_element(By.PARTIAL_LINK_TEXT, "Findings").click()
        # Click on `Import Scan Results` link text
        driver.find_element(By.LINK_TEXT, "Import Scan Results").click()
        # Select `ZAP Scan` as Scan Type
        Select(driver.find_element(By.ID, "id_scan_type")).select_by_visible_text("ZAP Scan")
        # Select `Default` as the Environment
        Select(driver.find_element(By.ID, "id_environment")).select_by_visible_text("Development")
        # upload scan file
        file_path = dir_path / "zap_sample.xml"
        driver.find_element(By.NAME, "file").send_keys(str(file_path))
        # Click Submit button
        with WaitForPageLoad(driver, timeout=50):
            driver.find_elements(By.CSS_SELECTOR, "button.btn.btn-primary")[1].click()
        # Query the site to determine if the finding has been added
        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="ZAP Scan processed a total of 4 findings"))

    @on_exception_html_source_logger
    def test_delete_finding(self):
        # The Name of the Finding created by test_add_product_finding => 'App Vulnerable to XSS'
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to All Finding page
        # driver.get(self.base_url + "finding")
        self.goto_all_findings_list(driver)

        # Select and click on the particular finding to edit
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        # Click on the 'dropdownMenu1 button'
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on `Delete Finding`
        driver.find_element(By.LINK_TEXT, "Delete Finding").click()
        # Click 'Yes' on Alert popup
        driver.switch_to.alert.accept()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        # self.assertTrue(self.is_success_message_present(text='Finding deleted successfully')) # there's no alert when deleting this way
        self.assertTrue(self.is_text_present_on_page(text="Finding deleted successfully"))
        # check that user was redirect back to url where it came from based on return_url

    def test_list_components(self):
        driver = self.driver
        self.goto_component_overview(driver)
        self.assertTrue(self.is_element_by_css_selector_present("table"))


def add_finding_tests_to_suite(suite, *, jira=False, github=False, block_execution=False):
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=jira, github=github, block_execution=block_execution)

    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase("delete_finding_template_if_exists"))
    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(UserTest("test_create_user_with_writer_global_role"))
    suite.addTest(FindingTest("test_list_findings_all"))
    suite.addTest(FindingTest("test_list_findings_open"))
    suite.addTest(FindingTest("test_quick_report"))
    suite.addTest(FindingTest("test_csv_export"))
    suite.addTest(FindingTest("test_excel_export"))
    suite.addTest(FindingTest("test_list_components"))
    suite.addTest(FindingTest("test_edit_finding"))
    suite.addTest(FindingTest("test_add_note_to_finding"))
    suite.addTest(FindingTest("test_add_image"))
    suite.addTest(FindingTest("test_delete_image"))
    suite.addTest(FindingTest("test_mark_finding_for_review"))
    suite.addTest(FindingTest("test_clear_review_from_finding"))
    suite.addTest(FindingTest("test_close_finding"))
    suite.addTest(FindingTest("test_list_findings_closed"))
    suite.addTest(FindingTest("test_open_finding"))
    suite.addTest(ProductTest("test_enable_simple_risk_acceptance"))
    suite.addTest(FindingTest("test_simple_accept_finding"))
    suite.addTest(FindingTest("test_list_findings_accepted"))
    suite.addTest(FindingTest("test_list_findings_all"))
    suite.addTest(FindingTest("test_unaccept_finding"))
    suite.addTest(FindingTest("test_make_finding_a_template"))
    suite.addTest(FindingTest("test_apply_template_to_a_finding"))
    suite.addTest(FindingTest("test_create_finding_from_template"))
    suite.addTest(FindingTest("test_import_scan_result"))
    suite.addTest(FindingTest("test_delete_finding"))
    suite.addTest(FindingTest("test_delete_finding_template"))
    suite.addTest(ProductTest("test_delete_product"))
    suite.addTest(UserTest("test_user_with_writer_role_delete"))
    return suite


def suite():
    suite = unittest.TestSuite()
    add_finding_tests_to_suite(suite, jira=False, github=False, block_execution=False)
    add_finding_tests_to_suite(suite, jira=True, github=True, block_execution=True)
    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)

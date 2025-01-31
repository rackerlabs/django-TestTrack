import sys
import time
import unittest

from base_test_class import BaseTestCase, on_exception_html_source_logger, set_suite_settings
from notifications_test import NotificationTest
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select


class WaitForPageLoad:
    def __init__(self, browser, timeout):
        self.browser = browser
        self.timeout = time.time() + timeout

    def __enter__(self):
        self.old_page = self.browser.find_element(By.TAG_NAME, "html")

    def page_has_loaded(self):
        new_page = self.browser.find_element(By.TAG_NAME, "html")
        return new_page.id != self.old_page.id

    def __exit__(self, *_):
        while time.time() < self.timeout:
            if self.page_has_loaded():
                return True
            time.sleep(0.2)
        msg = f"Timeout waiting for {self.timeout}s"
        raise Exception(msg)


class ProductTest(BaseTestCase):

    @on_exception_html_source_logger
    def test_create_product(self):
        # make sure no left overs from previous runs are left behind
        self.delete_product_if_exists()

        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # "Click" the dropdown button to see options
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the add prodcut button
        driver.find_element(By.LINK_TEXT, "Add Product").click()
        # Fill in th product name
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("QA Test")
        # Tab into the description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element(By.ID, "id_name").send_keys("\tThis is just a test. Be very afraid.")
        # Select an option in the poroduct type
        # some wild guess to print some debug info
        Select(driver.find_element(By.ID, "id_prod_type")).select_by_visible_text("Research and Development")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the product has been added

        # Assert ot the query to dtermine status of failure
        # Also confirm success even if Product is returned as already exists for test sake
        self.assertTrue(self.is_success_message_present(text="Product added successfully")
            or self.is_success_message_present(text="Product with this Name already exists."))
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_list_products(self):
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # list products which will make sure there are no javascript errors such as before in https://github.com/DefectDojo/django-DefectDojo/issues/2050

    @on_exception_html_source_logger
    def test_list_components(self):
        driver = self.driver
        self.goto_product_overview(driver)
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        driver.find_element(By.LINK_TEXT, "Components").click()
        driver.find_element(By.ID, "product_component_view").click()
        self.assertTrue(self.is_element_by_css_selector_present("table"))

    # For product consistency sake, We won't be editting the product title
    # instead We can edit the product description
    @on_exception_html_source_logger
    def test_edit_product_description(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        # driver.execute_script("window.scrollTo(0, 0)")
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on the 'Edit' option
        driver.find_element(By.LINK_TEXT, "Edit").click()
        # Edit product description
        driver.find_element(By.ID, "id_name").send_keys(Keys.TAB, "Updated Desription: ")
        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the product has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Product updated successfully")
            or self.is_success_message_present(text="Product with this Name already exists."))
        self.assertFalse(self.is_error_message_present())

    # For product consistency sake, We won't be editting the product title
    # instead We can edit the product description
    @on_exception_html_source_logger
    def test_enable_simple_risk_acceptance(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        # driver.execute_script("window.scrollTo(0, 0)")
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on the 'Edit' option
        driver.find_element(By.LINK_TEXT, "Edit").click()
        # Enable simple risk acceptance
        driver.find_element(By.XPATH, '//*[@id="id_enable_simple_risk_acceptance"]').click()

        # "Click" the submit button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the product has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Product updated successfully")
            or self.is_success_message_present(text="Product with this Name already exists."))
        self.assertFalse(self.is_error_message_present())

    @on_exception_html_source_logger
    def test_add_product_engagement(self):
        # Test To Add Engagement To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on the 'Engagement dropdown button'
        driver.find_element(By.PARTIAL_LINK_TEXT, "Engagement").click()
        # 'click' the Add New Engagement option
        driver.find_element(By.LINK_TEXT, "Add New Interactive Engagement").click()
        # Keep a good practice of clearing field before entering value
        # fill up at least all required input field options.
        # fields: 'Name', 'Description', 'Target Start', 'Target End', 'Testing Lead' and 'Status'
        # engagement name
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Beta Test")
        # engagement description
        # Tab into the description area to fill some text
        # Couldnt find a way to get into the box with selenium
        driver.find_element(By.ID, "id_name").send_keys(Keys.TAB, "Running Test on product before approving and push to production.")
        # engagement target start and target end already have defaults
        # we can safely skip
        # Testing Lead: This can be the logged in user
        Select(driver.find_element(By.ID, "id_lead")).select_by_visible_text("Admin User (admin)")
        # engagement status
        Select(driver.find_element(By.ID, "id_status")).select_by_visible_text("In Progress")
        # "Click" the Done button to Add the engagement
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the product has been added

        # Assert of the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Engagement added successfully"))

    @on_exception_html_source_logger
    def test_add_technology(self):
        # Test To add technology to product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Click on the 'Engagement dropdown button'
        driver.find_element(By.ID, "addTechnology").click()
        # Keep a good practice of clearing field before entering value
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Technology Test")
        driver.find_element(By.ID, "id_version").clear()
        driver.find_element(By.ID, "id_version").send_keys("2.1.0-RELEASE")
        # "Click" the Submit button to Add the technology
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Assert of the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Technology added successfully"))
        # Query the site to determine if the member has been added
        self.assertEqual(driver.find_elements(By.NAME, "technology_name")[0].text, "Technology Test")
        self.assertEqual(driver.find_elements(By.NAME, "technology_version")[0].text, "v.2.1.0-RELEASE")

    @on_exception_html_source_logger
    def test_edit_technology(self):
        # Test To edit technology to product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Open the menu to manage technologies and click the 'Edit' button
        driver.find_elements(By.NAME, "dropdownManageTechnologies")[0].click()
        driver.find_elements(By.NAME, "editTechnology")[0].click()
        # Keep a good practice of clearing field before entering value
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Technology Changed")
        driver.find_element(By.ID, "id_version").clear()
        driver.find_element(By.ID, "id_version").send_keys("2.2.0-RELEASE")
        # "Click" the Submit button to change the technology
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Assert of the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Technology changed successfully"))
        # Query the site to determine if the member has been added
        self.assertEqual(driver.find_elements(By.NAME, "technology_name")[0].text, "Technology Changed")
        self.assertEqual(driver.find_elements(By.NAME, "technology_version")[0].text, "v.2.2.0-RELEASE")

    @on_exception_html_source_logger
    def test_delete_technology(self):
        # Test To edit technology to product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # Open the menu to manage technologies and click the 'Delete' button
        driver.find_elements(By.NAME, "dropdownManageTechnologies")[0].click()
        driver.find_elements(By.NAME, "deleteTechnology")[0].click()
        # "Click" the Submit button to delete the technology
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-danger").click()
        # Assert of the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Technology deleted successfully"))
        # Query the site to determine if the technology has been deleted
        self.assertFalse(driver.find_elements(By.NAME, "technology_name"))

    @on_exception_html_source_logger
    def test_add_product_finding(self):
        # Test To Add Finding To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Click on the 'Finding dropdown button'
        driver.find_element(By.PARTIAL_LINK_TEXT, "Findings").click()
        # Click on `Add New Finding`
        driver.find_element(By.LINK_TEXT, "Add New Finding").click()
        # Keep a good practice of clearing field before entering value
        # fill up at least all required input field options.
        # fields: 'Title', 'Date', 'Severity', 'Description', 'Mitigation' and 'Impact'
        # finding Title
        driver.find_element(By.ID, "id_title").clear()
        driver.find_element(By.ID, "id_title").send_keys("App Vulnerable to XSS")
        # finding Date as a default value and can be safely skipped
        # finding Severity
        Select(driver.find_element(By.ID, "id_severity")).select_by_visible_text("High")
        # cvssv3 field
        driver.find_element(By.ID, "id_cvssv3").send_keys("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        # finding Description
        driver.find_element(By.ID, "id_cvssv3").send_keys(Keys.TAB, "This is just a Test Case Finding")
        # finding Vulnerability Ids
        driver.find_element(By.ID, "id_vulnerability_ids").send_keys("REF-1\nREF-2")
        # Finding Mitigation
        # Use Javascript to bypass the editor by making Setting textArea style from none to inline
        # Any Text written to textarea automatically reflects in Editor field.
        driver.execute_script("document.getElementsByName('mitigation')[0].style.display = 'inline'")
        driver.find_element(By.NAME, "mitigation").send_keys(Keys.TAB, "How to mitigate this finding")
        # Finding Impact
        # Use Javascript to bypass the editor by making Setting textArea style from none to inline
        # Any Text written to textarea automatically reflects in Editor field.
        driver.execute_script("document.getElementsByName('impact')[0].style.display = 'inline'")
        driver.find_element(By.NAME, "impact").send_keys(Keys.TAB, "This has a very critical effect on production")
        # Add an endpoint
        driver.find_element(By.ID, "id_endpoints_to_add").send_keys("product.finding.com")
        # "Click" the Done button to Add the finding with other defaults
        with WaitForPageLoad(driver, timeout=30):
            driver.find_element(By.XPATH, "//input[@name='_Finished']").click()
        # Query the site to determine if the finding has been added

        # Assert to the query to dtermine status of failure
        self.assertTrue(self.is_text_present_on_page(text="App Vulnerable to XSS"))
        # Select and click on the finding to check if endpoint has been added
        driver.find_element(By.LINK_TEXT, "App Vulnerable to XSS").click()
        self.assertTrue(self.is_text_present_on_page(text="product.finding.com"))
        self.assertTrue(self.is_text_present_on_page(text="REF-1"))
        self.assertTrue(self.is_text_present_on_page(text="REF-2"))
        self.assertTrue(self.is_text_present_on_page(text="Additional Vulnerability Ids"))

    @on_exception_html_source_logger
    def test_add_product_endpoints(self):
        # Test To Add Endpoints To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # Click on the 'Endpoints' dropdown button
        driver.find_element(By.PARTIAL_LINK_TEXT, "Endpoints").click()
        # 'click' the Add New Endpoint option
        driver.find_element(By.LINK_TEXT, "Add New Endpoint").click()
        # Keep a good practice of clearing field before entering value
        # Endpoints
        driver.find_element(By.ID, "id_endpoint").clear()
        driver.find_element(By.ID, "id_endpoint").send_keys("strange.prod.dev\n123.45.6.30")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Endpoint added successfully"))

    @on_exception_html_source_logger
    def test_add_product_custom_field(self):
        # Test To Add Custom Fields To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # 'click' the Add Custom Fields
        driver.find_element(By.LINK_TEXT, "Add Custom Fields").click()
        # Keep a good practice of clearing field before entering value
        # Custom Name
        driver.find_element(By.ID, "id_name").clear()
        driver.find_element(By.ID, "id_name").send_keys("Security Level")
        # Custom Value
        driver.find_element(By.ID, "id_value").clear()
        driver.find_element(By.ID, "id_value").send_keys("Loose")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        # Also confirm success even if variable is returned as already exists for test sake
        self.assertTrue(self.is_success_message_present(text="Metadata added successfully")
            or self.is_success_message_present(text="A metadata entry with the same name exists already for this object."))

    @on_exception_html_source_logger
    def test_edit_product_custom_field(self):
        # Test To Edit Product Custom Fields
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # 'click' the Edit Custom Fields
        driver.find_element(By.LINK_TEXT, "Edit Custom Fields").click()
        # Keep a good practice of clearing field before entering value
        # Edit Custom Value of First field
        driver.find_element(By.XPATH, "//input[@value='Loose']").clear()
        driver.find_element(By.XPATH, "//input[@value='Loose']").send_keys("Strong")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine success or failure
        self.assertTrue(self.is_success_message_present(text="Metadata edited successfully")
            or self.is_success_message_present(text="A metadata entry with the same name exists already for this object."))

    @on_exception_html_source_logger
    def test_add_product_tracking_files(self):
        # Test To Add tracking files To product
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # 'click' the Add Product Tracking Files
        driver.find_element(By.LINK_TEXT, "Add Product Tracking Files").click()
        # Keep a good practice of clearing field before entering value
        # Just fill up to main required fields: 'File path' nd 'review status'
        # Full File path
        driver.find_element(By.ID, "id_path").clear()
        driver.find_element(By.ID, "id_path").send_keys("/strange/folder/")
        # REview Status
        Select(driver.find_element(By.ID, "id_review_status")).select_by_visible_text("Untracked")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the finding has been added

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Added Tracked File to a Product"))

    @on_exception_html_source_logger
    def test_edit_product_tracking_files(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        driver.find_element(By.ID, "dropdownMenu1").click()
        # 'click' the Edit Product Tracking Files
        driver.find_element(By.LINK_TEXT, "View Product Tracking Files").click()
        # Keep a good practice of clearing field before entering value
        # Edit Custom Value of First field
        driver.find_element(By.LINK_TEXT, "Edit").click()
        # Edit full file path
        driver.find_element(By.ID, "id_path").clear()
        driver.find_element(By.ID, "id_path").send_keys("/unknown/folder/")
        # submit
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
        # Query the site to determine if the Tracking file has been updated

        # Assert ot the query to dtermine status of failure
        self.assertTrue(self.is_success_message_present(text="Tool Product Configuration Successfully Updated"))

    def test_product_metrics(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select and click on the particular product to edit
        driver.find_element(By.LINK_TEXT, "QA Test").click()
        # "Click" the dropdown option
        # driver.find_element(By.XPATH, "//span[contains(., 'Metrics')]").click()
        driver.find_element(By.PARTIAL_LINK_TEXT, "Metrics").click()

    @on_exception_html_source_logger
    def test_delete_product(self, name="QA Test"):
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select the specific product to delete
        driver.find_element(By.LINK_TEXT, name).click()
        # Click the drop down menu
        # driver.execute_script("window.scrollTo(0, 0)")
        driver.find_element(By.ID, "dropdownMenu1").click()
        # "Click" the Delete option
        driver.find_element(By.LINK_TEXT, "Delete").click()
        # "Click" the delete button to complete the transaction
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-danger").click()
        # Query the site to determine if the product has been added

        # Assert ot the query to determine status of failure
        self.assertTrue(self.is_success_message_present(text="Product and relationships removed."))

    @on_exception_html_source_logger
    def test_product_notifications_change(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        NotificationTest("enable_notification", "mail").enable_notification()
        driver = self.driver

        self.goto_product_overview(driver)
        # Select the specific product to delete
        driver.find_element(By.LINK_TEXT, "QA Test").click()

        driver.find_element(By.XPATH, "//input[@name='engagement_added' and @value='mail']").click()
        # clicking == ajax call to submit, but I think selenium gets this

        self.assertTrue(self.is_success_message_present(text="Notification settings updated"))
        self.assertTrue(driver.find_element(By.XPATH, "//input[@name='engagement_added' and @value='mail']").is_selected())
        self.assertFalse(driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").is_selected())
        self.assertFalse(driver.find_element(By.XPATH, "//input[@name='test_added' and @value='mail']").is_selected())

        driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").click()

        self.assertTrue(self.is_success_message_present(text="Notification settings updated"))
        self.assertTrue(driver.find_element(By.XPATH, "//input[@name='engagement_added' and @value='mail']").is_selected())
        self.assertTrue(driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").is_selected())
        self.assertFalse(driver.find_element(By.XPATH, "//input[@name='test_added' and @value='mail']").is_selected())

    def test_critical_product_metrics(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "critical_product_metrics")

    def test_product_type_metrics(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "metrics/product/type")

    def test_product_type_counts_metrics(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "metrics/product/type/counts")

        my_select = Select(driver.find_element(By.ID, "id_product_type"))
        my_select.select_by_index(1)

        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def test_simple_metrics(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "metrics/simple")

    def test_engineer_metrics(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "metrics/engineer")

    def test_metrics_dashboard(self):
        # Test To Edit Product Tracking Files
        # login to site, password set to fetch from environ
        driver = self.driver
        # Navigate to the product page
        driver.get(self.base_url + "metrics?date=5&view=dashboard")


def add_product_tests_to_suite(suite, *, jira=False, github=False, block_execution=False):
    # Add each test and the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase("test_login"))
    set_suite_settings(suite, jira=jira, github=github, block_execution=block_execution)

    suite.addTest(ProductTest("test_create_product"))
    suite.addTest(ProductTest("test_edit_product_description"))
    suite.addTest(ProductTest("test_add_technology"))
    suite.addTest(ProductTest("test_edit_technology"))
    suite.addTest(ProductTest("test_delete_technology"))
    suite.addTest(ProductTest("test_add_product_engagement"))
    suite.addTest(ProductTest("test_add_product_finding"))
    suite.addTest(ProductTest("test_add_product_endpoints"))
    suite.addTest(ProductTest("test_add_product_custom_field"))
    suite.addTest(ProductTest("test_edit_product_custom_field"))
    suite.addTest(ProductTest("test_add_product_tracking_files"))
    suite.addTest(ProductTest("test_edit_product_tracking_files"))
    suite.addTest(ProductTest("test_list_products"))
    suite.addTest(ProductTest("test_list_components"))
    suite.addTest(ProductTest("test_product_notifications_change"))
    suite.addTest(ProductTest("test_product_metrics"))

    # we add metrics tests here as we now have a product that triggers some logic inside metrics
    suite.addTest(ProductTest("test_critical_product_metrics"))
    suite.addTest(ProductTest("test_product_type_metrics"))
    suite.addTest(ProductTest("test_product_type_counts_metrics"))
    suite.addTest(ProductTest("test_simple_metrics"))
    suite.addTest(ProductTest("test_engineer_metrics"))
    suite.addTest(ProductTest("test_metrics_dashboard"))

    suite.addTest(ProductTest("test_delete_product"))
    return suite


def suite():
    suite = unittest.TestSuite()
    add_product_tests_to_suite(suite, jira=False, github=False, block_execution=False)
    add_product_tests_to_suite(suite, jira=True, github=True, block_execution=True)

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)

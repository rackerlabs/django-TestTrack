import logging
import os
import re
import unittest

from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException, NoSuchElementException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

# import time
logger = logging.getLogger(__name__)


dd_driver = None
dd_driver_options = None


def on_exception_html_source_logger(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)

        except Exception:
            logger.info(f"exception occured at url: {self.driver.current_url}")
            logger.info(f"page source: {self.driver.page_source}")
            f = open("selenium_page_source.html", "w", encoding="utf-8")
            f.writelines(self.driver.page_source)
            # time.sleep(30)
            raise

    return wrapper


def set_suite_settings(suite, *, jira=False, github=False, block_execution=False):
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


class BaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):

        # Path for automatic downloads, mapped to the media path
        cls.export_path = "/app"

        global dd_driver
        if not dd_driver:
            # setupModule and tearDownModule are not working in our scenario, so for now we use setupClass and a global variable
            # global variables are dirty, but in unit tests scenario's like these they are acceptable
            logger.info(f"launching browser for: {cls.__name__}")
            global dd_driver_options
            dd_driver_options = Options()

            # headless means no UI, if you want to see what is happening remove headless. Adding detach will leave the window open after the test
            dd_driver_options.add_argument("--headless")
            # dd_driver_options.add_experimental_option("detach", True)

            # the next 2 maybe needed in some scenario's for example on WSL or other headless situations
            dd_driver_options.add_argument("--no-sandbox")
            dd_driver_options.add_argument("--disable-dev-shm-usage")
            dd_driver_options.add_argument(
                "--disable-gpu",
            )  # on windows sometimes chrome can't start with certain gpu driver versions, even in headless mode

            # start maximized or at least with sufficient with because datatables will hide certain controls when the screen is too narrow
            dd_driver_options.add_argument("--window-size=1280,1024")
            # dd_driver_options.add_argument("--start-maximized")

            dd_driver_options.set_capability(name="acceptInsecureCerts", value=True)

            # some extra logging can be turned on if you want to query the browser javascripe console in your tests
            desired = webdriver.DesiredCapabilities.CHROME
            desired["goog:loggingPrefs"] = {"browser": "ALL"}

            # set automatic downloads to test csv and excel export
            prefs = {"download.default_directory": cls.export_path}
            dd_driver_options.add_experimental_option("prefs", prefs)

            # change path of chromedriver according to which directory you have chromedriver.
            logger.info(
                f"starting chromedriver with options: {vars(dd_driver_options)} {desired}",
            )

            # TODO: - this filter needs to be removed
            import warnings
            warnings.filterwarnings("ignore", message="executable_path has been deprecated, please pass in a Service object")
            warnings.filterwarnings("ignore", message="use options instead of chrome_options")
            warnings.filterwarnings("ignore", message="desired_capabilities has been deprecated, please pass in a Service object")
            warnings.filterwarnings("ignore", message="It is deprecated to return a value that is not None from a test case")

            dd_driver = webdriver.Chrome(
                os.environ["CHROMEDRIVER"],
                chrome_options=dd_driver_options,
                desired_capabilities=desired,
            )
            # best practice is only use explicit waits
            dd_driver.implicitly_wait(1)

        cls.driver = dd_driver
        cls.base_url = os.environ["DD_BASE_URL"]

    def setUp(self):
        self.verificationErrors = []
        self.accept_next_alert = True
        self.accept_javascript_errors = False
        self.driver.execute_script("console.clear()")
        # clear browser console logs?

    def login_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys(os.environ["DD_ADMIN_USER"])
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys(
            os.environ["DD_ADMIN_PASSWORD"],
        )
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()

        self.assertFalse(
            self.is_element_by_css_selector_present(
                ".alert-danger", "Please enter a correct username and password",
            ),
        )
        return driver

    def login_standard_page(self):
        driver = self.driver
        driver.get(self.base_url + "login")
        driver.find_element(By.ID, "id_username").clear()
        driver.find_element(By.ID, "id_username").send_keys("propersahm")
        driver.find_element(By.ID, "id_password").clear()
        driver.find_element(By.ID, "id_password").send_keys("Def3ctD0jo&")
        driver.find_element(By.CSS_SELECTOR, "button.btn.btn-success").click()

        self.assertFalse(
            self.is_element_by_css_selector_present(
                ".alert-danger", "Please enter a correct username and password",
            ),
        )
        return driver

    def test_login(self):
        return self.login_page()

    def logout(self):
        driver = self.driver
        driver.get(self.base_url + "logout")

        self.assertTrue(self.is_text_present_on_page("Login"))
        return driver

    def test_logout(self):
        return self.logout()

    @on_exception_html_source_logger
    def delete_product_if_exists(self, name="QA Test"):
        driver = self.driver
        # Navigate to the product page
        self.goto_product_overview(driver)
        # Select the specific product to delete
        qa_products = driver.find_elements(By.LINK_TEXT, name)

        if len(qa_products) > 0:
            self.test_delete_product(name)

    @on_exception_html_source_logger
    def delete_finding_template_if_exists(self, name="App Vulnerable to XSS"):
        driver = self.driver

        driver.get(self.base_url + "template")
        # Click on `Delete Template` button
        templates = driver.find_elements(By.LINK_TEXT, name)
        if len(templates) > 0:
            driver.find_element(By.ID, "id_delete").click()
            # Click 'Yes' on Alert popup
            driver.switch_to.alert.accept()

    # used to load some page just to get started
    # we choose /user because it's lightweight and fast
    def goto_some_page(self):
        driver = self.driver
        driver.get(self.base_url + "user")
        return driver

    def goto_product_overview(self, driver):
        driver.get(self.base_url + "product")
        self.wait_for_datatable_if_content("no_products", "products_wrapper")
        return driver

    def goto_product_type_overview(self, driver):
        driver.get(self.base_url + "product/type")
        return driver

    def goto_component_overview(self, driver):
        driver.get(self.base_url + "components")
        return driver

    def goto_google_sheets_configuration_form(self, driver):
        # if something is terribly wrong, it may still fail, even if system_settings is disabled.
        # See https://github.com/DefectDojo/django-DefectDojo/issues/3742 for reference.
        driver.get(self.base_url + "configure_google_sheets")
        return driver

    def goto_active_engagements_overview(self, driver):
        driver.get(self.base_url + "engagement/active")
        return driver

    def goto_all_engagements_overview(self, driver):
        driver.get(self.base_url + "engagement/all")
        return driver

    def goto_all_engagements_by_product_overview(self, driver):
        return self.goto_engagements_internal(driver, "engagements_all")

    def goto_engagements_internal(self, driver, rel_url):
        driver.get(self.base_url + rel_url)
        self.wait_for_datatable_if_content("no_engagements", "engagements_wrapper")
        return driver

    def goto_all_findings_list(self, driver):
        driver.get(self.base_url + "finding")
        self.wait_for_datatable_if_content("no_findings", "open_findings_wrapper")
        return driver

    def wait_for_datatable_if_content(self, no_content_id, wrapper_id):
        if not self.is_element_by_id_present(no_content_id):
            # wait for product_wrapper div as datatables javascript modifies the DOM on page load.
            WebDriverWait(self.driver, 30).until(
                EC.presence_of_element_located((By.ID, wrapper_id)),
            )

    def is_element_by_css_selector_present(self, selector, text=None):
        elems = self.driver.find_elements(By.CSS_SELECTOR, selector)
        if len(elems) == 0:
            return False

        if text is None:
            return True

        for elem in elems:
            logger.info(elem.text)
            if text in elem.text:
                return True

        return False

    def is_element_by_id_present(self, id):
        try:
            self.driver.find_element(By.ID, id)
            return True
        except NoSuchElementException:
            return False

    def is_success_message_present(self, text=None):
        return self.is_element_by_css_selector_present(".alert-success", text=text)

    def is_error_message_present(self, text=None):
        return self.is_element_by_css_selector_present(".alert-danger", text=text)

    def is_help_message_present(self, text=None):
        return self.is_element_by_css_selector_present(".help-block", text=text)

    def is_text_present_on_page(self, text):
        # DEBUG: couldn't find:  Product type added successfully. path:  //*[contains(text(),'Product type added successfully.')]
        # can't get this xpath to work
        # path = "//*[contains(text(), '" + text + "')]"
        # elems = self.driver.find_elements(By.XPATH, path)
        # if len(elems) == 0:
        #     logger.debug("couldn't find: ", text, "path: ", path)

        body = self.driver.find_element(By.TAG_NAME, "body")
        return re.search(text, body.text)

    def element_exists_by_id(self, id):
        elems = self.driver.find_elements(By.ID, id)
        return len(elems) > 0

    def change_system_setting(self, id, *, enable=True):
        logger.info("changing system setting " + id + " enable: " + str(enable))
        driver = self.driver
        driver.get(self.base_url + "system_settings")

        is_enabled = driver.find_element(By.ID, id).is_selected()
        if (enable and not is_enabled) or (not enable and is_enabled):
            # driver.find_element(By.XPATH, '//*[@id=' + id + ']').click()
            driver.find_element(By.ID, id).click()
            # save settings
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            # check if it's enabled after reload

        is_enabled = driver.find_element(By.ID, id).is_selected()

        if enable:
            self.assertTrue(is_enabled)

        if not enable:
            self.assertFalse(is_enabled)

        return is_enabled

    def enable_system_setting(self, id):
        return self.change_system_setting(id, enable=True)

    def disable_system_setting(self, id):
        return self.change_system_setting(id, enable=False)

    def enable_jira(self):
        return self.enable_system_setting("id_enable_jira")

    def disable_jira(self):
        return self.disable_system_setting("id_enable_jira")

    def disable_github(self):
        return self.disable_system_setting("id_enable_github")

    def enable_github(self):
        return self.enable_system_setting("id_enable_github")

    def set_block_execution(self, *, block_execution=True):
        # we set the admin user (ourselves) to have block_execution checked
        # this will force dedupe to happen synchronously, among other things like notifications, rules, ...
        logger.info(f"setting block execution to: {block_execution}")
        driver = self.driver
        driver.get(self.base_url + "profile")
        if (
            driver.find_element(By.ID, "id_block_execution").is_selected()
            != block_execution
        ):
            driver.find_element(By.XPATH, '//*[@id="id_block_execution"]').click()
            # save settings
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()
            # check if it's enabled after reload
            self.assertEqual(
                driver.find_element(By.ID, "id_block_execution").is_selected(),
                block_execution,
            )
        return driver

    def enable_block_execution(self):
        self.set_block_execution()

    def disable_block_execution(self):
        self.set_block_execution(block_execution=False)

    def enable_deduplication(self):
        return self.enable_system_setting("id_enable_deduplication")

    def disable_deduplication(self):
        return self.disable_system_setting("id_enable_deduplication")

    def enable_false_positive_history(self):
        return self.enable_system_setting("id_false_positive_history")

    def disable_false_positive_history(self):
        return self.disable_system_setting("id_false_positive_history")

    def enable_retroactive_false_positive_history(self):
        return self.enable_system_setting("id_retroactive_false_positive_history")

    def disable_retroactive_false_positive_history(self):
        return self.disable_system_setting("id_retroactive_false_positive_history")

    def is_alert_present(self):
        try:
            self.driver.switch_to_alert()
        except NoAlertPresentException:
            return False
        return True

    def close_alert_and_get_its_text(self):
        try:
            alert = self.driver.switch_to_alert()
            alert_text = alert.text
            if self.accept_next_alert:
                alert.accept()
            else:
                alert.dismiss()
            return alert_text
        finally:
            self.accept_next_alert = True

    def assertNoConsoleErrors(self):
        """
        Sample output for levels (i.e. errors are SEVERE)
        {'level': 'DEBUG', 'message': 'http://localhost:8080/product/type/4/edit 560:12 "debug"', 'source': 'console-api', 'timestamp': 1583952828410}
        {'level': 'INFO', 'message': 'http://localhost:8080/product/type/4/edit 561:16 "info"', 'source': 'console-api', 'timestamp': 1583952828410}
        {'level': 'WARNING', 'message': 'http://localhost:8080/product/type/4/edit 562:16 "warning"', 'source': 'console-api', 'timestamp': 1583952828410}
        {'level': 'SEVERE', 'message': 'http://localhost:8080/product/type/4/edit 563:16 "error"', 'source': 'console-api', 'timestamp': 1583952828410}
        """
        for entry in WebdriverOnlyNewLogFacade(self.driver).get_log("browser"):
            """
            Images are now working after https://github.com/DefectDojo/django-DefectDojo/pull/3954,
            but http://localhost:8080/static/dojo/img/zoom-in.cur still produces a 404

            The addition of the trigger exception is due to the Report Builder tests.
            The addition of the innerHTML exception is due to the test for quick reports in finding_test.py
            """
            accepted_javascript_messages = r"(zoom\-in\.cur.*)404\ \(Not\ Found\)|Uncaught TypeError: Cannot read properties of null \(reading \'trigger\'\)|Uncaught TypeError: Cannot read properties of null \(reading \'innerHTML\'\)"

            if entry["level"] == "SEVERE":
                # TODO: actually this seems to be the previous url
                # self.driver.save_screenshot("C:\\Data\\django-DefectDojo\\tests\\javascript-errors.png")
                # with open("C:\\Data\\django-DefectDojo\\tests\\javascript-errors.html", "w") as f:
                #    f.write(self.driver.page_source)

                logger.info(entry)
                logger.info(
                    "There was a SEVERE javascript error in the console, please check all steps fromt the current test to see where it happens",
                )
                logger.info(
                    "Currently there is no reliable way to find out at which url the error happened, but it could be: ."
                    + self.driver.current_url,
                )
                if self.accept_javascript_errors:
                    logger.warning(
                        "skipping SEVERE javascript error because accept_javascript_errors is True!",
                    )
                elif re.search(accepted_javascript_messages, entry["message"]):
                    logger.warning(
                        "skipping javascript errors related to known issues images, see https://github.com/DefectDojo/django-DefectDojo/blob/master/tests/base_test_class.py#L324",
                    )
                else:
                    self.assertNotEqual(entry["level"], "SEVERE")

        return True

    def tearDown(self):
        self.assertNoConsoleErrors()

        self.assertEqual([], self.verificationErrors)

    @classmethod
    def tearDownDriver(cls):
        logger.info(f"tearDownDriver: {cls.__name__}")
        global dd_driver
        if dd_driver:
            if (
                not dd_driver_options.experimental_options
                or not dd_driver_options.experimental_options.get("detach")
            ):
                logger.info("closing browser")
                dd_driver.quit()


class WebdriverOnlyNewLogFacade:

    last_timestamp = 0

    def __init__(self, webdriver):
        self._webdriver = webdriver

    def get_log(self, log_type):
        last_timestamp = self.last_timestamp
        entries = self._webdriver.get_log(log_type)
        filtered = []

        for entry in entries:
            # check the logged timestamp against the
            # stored timestamp
            if entry["timestamp"] > self.last_timestamp:
                filtered.append(entry)

                # save the last timestamp only if newer
                # in this set of logs
                if entry["timestamp"] > last_timestamp:
                    last_timestamp = entry["timestamp"]

        # store the very last timestamp
        self.last_timestamp = last_timestamp

        return filtered

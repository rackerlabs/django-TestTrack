import sys
import unittest

from base_test_class import BaseTestCase
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver import ActionChains
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


class NotificationTest(BaseTestCase):

    def __init__(self, method_name, notif_type):
        super().__init__(method_name)
        self.type = notif_type

    def enable_notification(self):
        driver = self.driver
        # Navigate to the System Settings
        driver.get(self.base_url + "system_settings")
        mail_control = driver.find_element(By.ID, f"id_enable_{self.type}_notifications")
        if not mail_control.is_selected():
            mail_control.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def disable_notification(self):
        driver = self.driver
        # Navigate to the System Settings
        driver.get(self.base_url + "system_settings")
        mail_control = driver.find_element(By.ID, f"id_enable_{self.type}_notifications")
        if mail_control.is_selected():
            mail_control.click()
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def test_disable_personal_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container

        driver = self.driver

        self.disable_notification()
        driver.get(self.base_url + "notifications")
        in_place = False
        try:
            driver.find_element(By.XPATH, f"//input[@name='product_added' and @value='{self.type}']")
            in_place = True
        except NoSuchElementException:
            in_place = False
        self.assertFalse(in_place)

    def test_enable_personal_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.enable_notification()
        driver.get(self.base_url + "notifications")
        try:
            driver.find_element(By.XPATH, f"//input[@name='product_added' and @value='{self.type}']")
        except NoSuchElementException:
            # msteam should be not in personal notifications
            self.assertEqual(self.type, "msteams")

    def test_disable_system_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container

        driver = self.driver

        self.disable_notification()
        driver.get(self.base_url + "notifications/system")
        in_place = False
        try:
            driver.find_element(By.XPATH, f"//input[@name='product_added' and @value='{self.type}']")
            in_place = True
        except NoSuchElementException:
            in_place = False
        self.assertFalse(in_place)

    def test_enable_system_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.enable_notification()
        in_place = False
        try:
            driver.find_element(By.XPATH, f"//input[@name='product_added' and @value='{self.type}']")
            in_place = True
        except NoSuchElementException:
            in_place = False
        self.assertFalse(in_place)

    def test_disable_template_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container

        driver = self.driver

        self.disable_notification()
        driver.get(self.base_url + "notifications/template")
        in_place = False
        try:
            driver.find_element(By.XPATH, f"//input[@name='product_added' and @value='{self.type}']")
            in_place = True
        except NoSuchElementException:
            in_place = False
        self.assertFalse(in_place)

    def test_enable_template_notification(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        self.enable_notification()
        driver.get(self.base_url + "notifications/template")
        try:
            driver.find_element(By.XPATH, f"//input[@name='product_added' and @value='{self.type}']")
        except NoSuchElementException:
            # msteam should be not in personal notifications
            self.assertEqual(self.type, "msteams")

    def test_user_mail_notifications_change(self):
        # Login to the site. Password will have to be modified
        # to match an admin password in your own container
        driver = self.driver

        wait = WebDriverWait(driver, 5)
        actions = ActionChains(driver)
        configuration_menu = driver.find_element(By.ID, "menu_configuration")
        actions.move_to_element(configuration_menu).perform()
        wait.until(EC.visibility_of_element_located((By.LINK_TEXT, "Notifications"))).click()

        originally_selected = {
            "product_added": driver.find_element(By.XPATH,
                                                 "//input[@name='product_added' and @value='mail']").is_selected(),
            "scan_added": driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").is_selected(),
        }

        driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']").click()
        driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").click()

        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

        self.assertTrue(self.is_success_message_present(text="Settings saved"))
        self.assertNotEqual(originally_selected["product_added"],
                            driver.find_element(By.XPATH, "//input[@name='product_added' and @value='mail']").is_selected())
        self.assertNotEqual(originally_selected["scan_added"],
                            driver.find_element(By.XPATH, "//input[@name='scan_added' and @value='mail']").is_selected())


def suite():
    suite = unittest.TestSuite()
    # Add each test the the suite to be run
    # success and failure is output by the test
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(NotificationTest("test_disable_personal_notification", "mail"))
    suite.addTest(NotificationTest("test_disable_personal_notification", "slack"))
    suite.addTest(NotificationTest("test_disable_personal_notification", "msteams"))
    suite.addTest(NotificationTest("test_disable_personal_notification", "webhooks"))
    # now test when enabled
    suite.addTest(NotificationTest("test_enable_personal_notification", "mail"))
    suite.addTest(NotificationTest("test_enable_personal_notification", "slack"))
    suite.addTest(NotificationTest("test_enable_personal_notification", "msteams"))
    suite.addTest(NotificationTest("test_enable_personal_notification", "webhooks"))
    # Now switch to system notifications
    suite.addTest(NotificationTest("test_disable_system_notification", "mail"))
    suite.addTest(NotificationTest("test_disable_system_notification", "slack"))
    suite.addTest(NotificationTest("test_disable_system_notification", "msteams"))
    suite.addTest(NotificationTest("test_disable_system_notification", "webhooks"))
    # now test when enabled
    suite.addTest(NotificationTest("test_enable_system_notification", "mail"))
    suite.addTest(NotificationTest("test_enable_system_notification", "slack"))
    suite.addTest(NotificationTest("test_enable_system_notification", "msteams"))
    suite.addTest(NotificationTest("test_enable_system_notification", "webhooks"))
    # not really for the user we created, but still related to user settings
    suite.addTest(NotificationTest("test_user_mail_notifications_change", "mail"))
    # now do short test for the template
    suite.addTest(NotificationTest("test_enable_template_notification", "mail"))
    suite.addTest(NotificationTest("test_enable_template_notification", "slack"))
    suite.addTest(NotificationTest("test_enable_template_notification", "msteams"))
    suite.addTest(NotificationTest("test_enable_template_notification", "webhooks"))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)

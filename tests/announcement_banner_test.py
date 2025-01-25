import sys
import unittest
from operator import xor

from base_test_class import BaseTestCase
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from user_test import UserTest


class AnnouncementBannerTest(BaseTestCase):

    def __init__(self, method_name, anno_type):
        super().__init__(method_name)
        self.type = anno_type

    def test_setup(self):
        driver = self.driver
        driver.get(self.base_url + "configure_announcement")
        if self.is_element_by_css_selector_present("input.btn.btn-danger"):
            driver.find_element(By.CSS_SELECTOR, "input.btn.btn-danger").click()

    def enable_announcement(self, message, dismissable, style):
        driver = self.driver
        driver.get(self.base_url + "configure_announcement")
        driver.find_element(By.ID, "id_message").send_keys(message)

        Select(driver.find_element(By.ID, "id_style")).select_by_visible_text(style)

        dismissable_control = driver.find_element(By.ID, "id_dismissable")
        if xor(bool(dismissable_control.is_selected()), bool(dismissable)):
            dismissable_control.click()

        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-primary").click()

    def disable_announcement(self):
        driver = self.driver
        driver.get(self.base_url + "configure_announcement")
        driver.find_element(By.CSS_SELECTOR, "input.btn.btn-danger").click()

    def test_create_announcement(self):
        driver = self.driver
        driver.get(self.base_url)
        self.assertFalse(self.is_element_by_css_selector_present(".announcement-banner"))

        text = "Big important announcement, definitely pay attention!"
        self.enable_announcement(text, dismissable=False, style=self.type)
        self.assertTrue(self.is_success_message_present("Announcement updated successfully."))

        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        driver.get(self.base_url)
        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        self.disable_announcement()
        self.assertTrue(self.is_success_message_present("Announcement removed for everyone."))

    def test_create_dismissable_announcement(self):
        driver = self.driver
        driver.get(self.base_url)
        self.assertFalse(self.is_element_by_css_selector_present(".announcement-banner"))

        text = "Big important announcement, definitely pay don't dismiss this one."
        self.enable_announcement(text, dismissable=True, style=self.type)
        self.assertTrue(self.is_success_message_present("Announcement updated successfully."))

        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        driver.get(self.base_url)
        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        close_button = driver.find_element(By.XPATH, "//div[contains(@class, 'announcement-banner')]/a/span[contains(text(), '×')]")  # noqa: RUF001
        close_button.click()
        dismiss_announcement_button = driver.find_element(By.XPATH, "//button[contains(@class, 'btn-danger') and contains(text(), 'Dismiss Announcement')]")
        dismiss_announcement_button.click()
        self.assertFalse(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))

        self.disable_announcement()
        self.assertTrue(self.is_success_message_present("Announcement removed for everyone."))

    def test_dismissing_announcement_does_not_dismiss_for_others(self):
        driver = self.driver
        driver.get(self.base_url)
        self.assertFalse(self.is_element_by_css_selector_present(".announcement-banner"))

        text = "Everyone sees this, right?"
        self.enable_announcement(text, dismissable=True, style=self.type)
        self.assertTrue(self.is_success_message_present("Announcement updated successfully."))

        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        close_button = driver.find_element(By.XPATH, "//div[contains(@class, 'announcement-banner')]/a/span[contains(text(), '×')]")  # noqa: RUF001
        close_button.click()
        dismiss_announcement_button = driver.find_element(By.XPATH, "//button[contains(@class, 'btn-danger') and contains(text(), 'Dismiss Announcement')]")
        dismiss_announcement_button.click()
        self.assertFalse(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        self.logout()

        self.login_standard_page()
        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        self.logout()

        self.login_page()
        self.assertFalse(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        self.disable_announcement()
        self.assertTrue(self.is_success_message_present("Announcement removed for everyone."))

    def test_announcement_ui_disabled_when_set(self):
        driver = self.driver
        driver.get(self.base_url)
        self.assertFalse(self.is_element_by_css_selector_present(".announcement-banner"))

        text = "The most important announcement of the year."
        self.enable_announcement(text, dismissable=False, style=self.type)
        self.assertTrue(self.is_success_message_present("Announcement updated successfully."))

        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        driver.get(self.base_url + "configure_announcement")
        driver.find_element(By.XPATH, "//input[contains(@id, 'id_message') and @disabled]")
        driver.find_element(By.XPATH, "//select[contains(@id, 'id_style') and @disabled]")
        driver.find_element(By.XPATH, "//input[contains(@id, 'id_dismissable') and @disabled]")

        self.disable_announcement()
        self.assertTrue(self.is_success_message_present("Announcement removed for everyone."))

    def test_announcement_empty_after_removal(self):
        driver = self.driver
        driver.get(self.base_url)
        self.assertFalse(self.is_element_by_css_selector_present(".announcement-banner"))

        text = "Surely no-one would delete this announcement quickly"
        self.enable_announcement(text, dismissable=False, style=self.type)
        self.assertTrue(self.is_success_message_present("Announcement updated successfully."))

        self.assertTrue(self.is_element_by_css_selector_present(f".announcement-banner.alert-{self.type.lower()}", text=text))
        self.disable_announcement()
        self.assertTrue(self.is_success_message_present("Announcement removed for everyone."))

        driver.get(self.base_url + "configure_announcement")
        driver.find_element(By.XPATH, "//input[contains(@id, 'id_message') and contains(@value,'')]")
        driver.find_element(By.XPATH, "//select[contains(@id, 'id_style')]/option[@selected and contains(text(), 'Info')]")
        driver.find_element(By.XPATH, "//input[contains(@id, 'id_dismissable') and not(@checked)]")

    def test_html_announcement(self):
        driver = self.driver
        driver.get(self.base_url)
        self.assertFalse(self.is_element_by_css_selector_present(".announcement-banner"))

        text = "Links in announcements? <a href='https://github.com/DefectDojo/django-DefectDojo' style='color: #224477;' target='_blank'>you bet!</a>"
        self.enable_announcement(text, dismissable=False, style=self.type)
        self.assertTrue(self.is_success_message_present("Announcement updated successfully."))

        driver.find_element(By.XPATH, "//div[contains(@class, 'announcement-banner')]/a[@href='https://github.com/DefectDojo/django-DefectDojo' and @style='color: #224477;' and @target='_blank']")
        self.disable_announcement()
        self.assertTrue(self.is_success_message_present("Announcement removed for everyone."))


def suite():
    suite = unittest.TestSuite()
    suite.addTest(BaseTestCase("test_login"))
    suite.addTest(AnnouncementBannerTest("test_setup", "Info"))
    suite.addTest(AnnouncementBannerTest("test_create_announcement", "Info"))
    suite.addTest(AnnouncementBannerTest("test_create_announcement", "Success"))
    suite.addTest(AnnouncementBannerTest("test_create_announcement", "Warning"))
    suite.addTest(AnnouncementBannerTest("test_create_announcement", "Danger"))
    suite.addTest(AnnouncementBannerTest("test_create_dismissable_announcement", "Info"))
    suite.addTest(AnnouncementBannerTest("test_create_dismissable_announcement", "Success"))
    suite.addTest(AnnouncementBannerTest("test_create_dismissable_announcement", "Warning"))
    suite.addTest(UserTest("test_create_user"))
    suite.addTest(AnnouncementBannerTest("test_dismissing_announcement_does_not_dismiss_for_others", "Info"))
    suite.addTest(AnnouncementBannerTest("test_announcement_ui_disabled_when_set", "Info"))
    suite.addTest(AnnouncementBannerTest("test_announcement_empty_after_removal", "Info"))
    suite.addTest(AnnouncementBannerTest("test_html_announcement", "Info"))

    return suite


if __name__ == "__main__":
    runner = unittest.TextTestRunner(descriptions=True, failfast=True, verbosity=2)
    ret = not runner.run(suite()).wasSuccessful()
    BaseTestCase.tearDownDriver()
    sys.exit(ret)

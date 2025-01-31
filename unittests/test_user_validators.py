from dojo.forms import ChangePasswordForm
from dojo.models import Dojo_User, System_Settings

from .dojo_test_case import DojoTestCase


class TestUserValidators(DojoTestCase):

    def form_test(
            self,
            password,
            confirm_password=None,
            current_password=None):
        if confirm_password is None:
            confirm_password = password
        if current_password is None:
            current_password = self.current_password
        return ChangePasswordForm({
            "current_password": current_password,
            "new_password": password,
            "confirm_password": confirm_password,
        },
            user=self.user,
        )

    def set_policy(
        self,
        minimum_password_length=0,
        maximum_password_length=50,
        *,
        number_character_required=False,
        special_character_required=False,
        lowercase_character_required=False,
        uppercase_character_required=False,
        non_common_password_required=False,
    ):
        self.system_settings = System_Settings.objects.get()
        self.system_settings.minimum_password_length = minimum_password_length
        self.system_settings.maximum_password_length = maximum_password_length
        self.system_settings.number_character_required = number_character_required
        self.system_settings.special_character_required = special_character_required
        self.system_settings.lowercase_character_required = lowercase_character_required
        self.system_settings.uppercase_character_required = uppercase_character_required
        self.system_settings.non_common_password_required = non_common_password_required
        self.system_settings.save()

    def setUp(self):
        super().setUp()
        self.current_password = "Or1gina1P@ssw0rd"
        self.user = Dojo_User.objects.create(username="password_tester")
        self.user.set_password(self.current_password)
        self.user.save()

    def test_validator_minimum_password_length(self):
        with self.subTest(policy="minimum_password_length 1≥0"):
            self.set_policy(minimum_password_length=0)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="minimum_password_length 1≥1"):
            self.set_policy(minimum_password_length=1)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="minimum_password_length 1≱2"):
            self.set_policy(minimum_password_length=2)
            form = self.form_test("x")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                "Password must be at least 2 characters long.")

    def test_validator_maximum_password_length(self):
        with self.subTest(policy="maximum_password_length 1≤2"):
            self.set_policy(maximum_password_length=2)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="maximum_password_length 1≤1"):
            self.set_policy(maximum_password_length=1)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="maximum_password_length 2≰1"):
            self.set_policy(maximum_password_length=0)
            form = self.form_test("x")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                "Password must be less than 0 characters long.")

    def test_validator_number_character_required(self):
        with self.subTest(policy="number_character_required=False"):
            self.set_policy(number_character_required=False)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="number_character_required=True"):
            self.set_policy(number_character_required=True)
            form = self.form_test("x")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                "Password must contain at least 1 digit, 0-9.")

    def test_validator_special_character_required(self):
        with self.subTest(policy="special_character_required=False"):
            self.set_policy(special_character_required=False)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="special_character_required=True"):
            self.set_policy(special_character_required=True)
            form = self.form_test("x")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                """The password must contain at least 1 special character, ()[]{}|`~!@#$%^&*_-+=;:'",<>./?.""")

    def test_validator_lowercase_character_required(self):
        with self.subTest(policy="lowercase_character_required=False"):
            self.set_policy(lowercase_character_required=False)
            self.assertTrue(self.form_test("X").is_valid())
        with self.subTest(policy="lowercase_character_required=True"):
            self.set_policy(lowercase_character_required=True)
            form = self.form_test("X")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                "Password must contain at least 1 lowercase letter, a-z.")

    def test_validator_uppercase_character_required(self):
        with self.subTest(policy="uppercase_character_required=False"):
            self.set_policy(uppercase_character_required=False)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="uppercase_character_required=True"):
            self.set_policy(uppercase_character_required=True)
            form = self.form_test("x")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                "Password must contain at least 1 uppercase letter, A-Z.")

    def test_validator_non_common_password_required(self):
        with self.subTest(policy="non_common_password_required=False"):
            self.set_policy(non_common_password_required=False)
            self.assertTrue(self.form_test("x").is_valid())
        with self.subTest(policy="non_common_password_required=True"):
            self.set_policy(non_common_password_required=True)
            form = self.form_test("x")
            self.assertFalse(form.is_valid())
            self.assertEqual(
                form.errors["new_password"][0],
                "This password is too common.")

    def test_form_invalid_current_pass(self):
        self.set_policy()
        form = self.form_test("x", current_password="not current password")  # noqa: S106
        self.assertFalse(form.is_valid())
        self.assertEqual(
            form.errors["__all__"][0],
            "Current password is incorrect.")

    def test_form_same_pass_as_before(self):
        self.set_policy()
        form = self.form_test(self.current_password)
        self.assertFalse(form.is_valid())
        self.assertEqual(
            form.errors["__all__"][0],
            "New password must be different from current password.")

    def test_form_diff_confirm_password(self):
        self.set_policy()
        form = self.form_test(password="x", confirm_password="y")  # noqa: S106
        self.assertFalse(form.is_valid())
        self.assertEqual(form.errors["__all__"][0], "Passwords do not match.")

from rest_framework.test import APITestCase

from apps.authentication.models import User


class TestModel(APITestCase):
    def test_create_user(self):
        user = User.objects.create_user(
            username="armin",
            email="arminpourbeik@gmail.com",
            password="p@assw0rd",
        )
        self.assertIsInstance(user, User)
        self.assertEqual(user.email, "arminpourbeik@gmail.com")
        self.assertFalse(user.is_staff)

    def test_create_user_without_username_raises_ValueError(self):
        self.assertRaises(
            ValueError,
            User.objects.create_user,
            username="",
            email="arminpourbeik@gmail.com",
            password="p@assw0rd",
        )
        self.assertRaisesMessage(
            ValueError, expected_message="The given username must be set"
        )

    def test_create_user_without_email_raises_ValueError(self):
        self.assertRaises(
            ValueError,
            User.objects.create_user,
            username="armin",
            email="",
            password="p@assw0rd",
        )
        self.assertRaisesMessage(
            ValueError, expected_message="The given email must be set"
        )

    def test_create_superuser(self):
        user = User.objects.create_superuser(
            username="armin",
            email="arminpourbeik@gmail.com",
            password="p@assw0rd",
        )
        self.assertIsInstance(user, User)
        self.assertEqual(user.email, "arminpourbeik@gmail.com")
        self.assertTrue(user.is_staff)

    def test_raises_error_with_message_when_no_username_is_supplied(self):
        with self.assertRaisesMessage(ValueError, "The given username must be set"):
            User.objects.create_user(
                username="",
                email="arminpourbeik@gmail.com",
                password="p@assw0rd",
            )

    def test_create_super_user_without_is_staff_is_true(self):
        with self.assertRaisesMessage(ValueError, "Superuser must have is_staff=True."):
            User.objects.create_superuser(
                username="armin",
                email="arminpourbeik@gmail.com",
                password="p@assw0rd",
                is_staff=False,
            )

    def test_create_super_user_without_is_superuser_is_true(self):
        with self.assertRaisesMessage(
            ValueError, "Superuser must have is_superuser=True."
        ):
            User.objects.create_superuser(
                username="armin",
                email="arminpourbeik@gmail.com",
                password="p@assw0rd",
                is_superuser=False,
            )

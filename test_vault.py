import os
import tempfile
import unittest
from pathlib import Path

from main import PasswordVault, MIN_MASTER_PASSWORD_LENGTH


class PasswordVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "vault.json"
        self.vault = PasswordVault(self.path)
        self.password = "Correct horse battery staple!"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_unlock_and_persist_entry(self):
        ok, recovery = self.vault.set_master_password(self.password)
        self.assertTrue(ok)
        self.assertRegex(recovery, r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$")
        self.assertTrue(self.vault.unlock_master(self.password))
        self.vault.add_password("Example", "alice", "s3cret", notes="test")

        reopened = PasswordVault(self.path)
        self.assertFalse(reopened.unlock_master("wrong password"))
        self.assertTrue(reopened.unlock_master(self.password))
        self.assertEqual(reopened.get_all()[0]["password"], "s3cret")

    def test_wrong_password_never_unlocks(self):
        self.vault.set_master_password(self.password)
        self.vault.lock()
        self.assertFalse(self.vault.unlock_master("short"))
        self.assertIsNone(self.vault.key)
        self.assertEqual(self.vault.passwords, [])

    def test_recovery_and_password_change_rotate_recovery_key(self):
        _, old_recovery = self.vault.set_master_password(self.password)
        self.vault.unlock_master(self.password)
        self.vault.add_password("Example", "alice", "s3cret")
        ok, new_recovery = self.vault.change_master_password("A new secure password!")
        self.assertTrue(ok)
        self.assertNotEqual(old_recovery, new_recovery)

        reopened = PasswordVault(self.path)
        self.assertFalse(reopened.unlock_recovery(old_recovery))
        self.assertTrue(reopened.unlock_recovery(new_recovery))
        self.assertEqual(reopened.get_all()[0]["username"], "alice")

    def test_atomic_file_permissions(self):
        self.vault.set_master_password(self.password)
        mode = os.stat(self.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_invalid_import_is_rejected(self):
        self.vault.set_master_password(self.password)
        bad = Path(self.temp_dir.name) / "bad.json"
        bad.write_text("not a vault", encoding="utf-8")
        with self.assertRaises(Exception):
            self.vault.import_from(bad)


if __name__ == "__main__":
    unittest.main()

"""Unit tests for export_secrets_env."""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path


class TestExportSecretsEnv(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_db(self, rows):
        db_path = os.path.join(self.tmpdir, "test.db")
        con = sqlite3.connect(db_path)
        con.execute(
            "CREATE TABLE services "
            "(id TEXT PRIMARY KEY, env_var TEXT, detected_config_path TEXT, "
            "detected_config_format TEXT, display_name TEXT)"
        )
        for row in rows:
            con.execute("INSERT INTO services VALUES (?,?,?,?,?)", row)
        con.commit()
        con.close()
        return db_path

    def _xml_config(self, name, key_value):
        path = os.path.join(self.tmpdir, name)
        Path(path).write_text(
            f'<?xml version="1.0"?><Config><ApiKey>{key_value}</ApiKey></Config>'
        )
        return path

    def test_two_services_alphabetical(self):
        from src.path_discovery import export_secrets_env

        prowlarr_cfg = self._xml_config("prowlarr_config.xml", "abc123def456789a")
        sonarr_cfg = self._xml_config("sonarr_config.xml", "xyz789abc123456b")

        db_path = self._make_db([
            ("prowlarr", "PROWLARR_API_KEY", prowlarr_cfg, "arr_xml", "Prowlarr"),
            ("sonarr", "SONARR_API_KEY", sonarr_cfg, "arr_xml", "Sonarr"),
        ])

        output_path = os.path.join(self.tmpdir, "export", "secrets.env")
        count = export_secrets_env(db_path, output_path)

        self.assertEqual(count, 2)
        self.assertTrue(os.path.exists(output_path))

        lines = [l for l in Path(output_path).read_text().splitlines() if l]
        # alphabetical by env_var: PROWLARR before SONARR
        self.assertEqual(lines[0], "PROWLARR_API_KEY=abc123def456789a")
        self.assertEqual(lines[1], "SONARR_API_KEY=xyz789abc123456b")

    def test_missing_config_file_skipped(self):
        from src.path_discovery import export_secrets_env

        sonarr_cfg = self._xml_config("sonarr_config.xml", "xyz789abc123456b")
        db_path = self._make_db([
            ("prowlarr", "PROWLARR_API_KEY", "/nonexistent/config.xml", "arr_xml", "Prowlarr"),
            ("sonarr", "SONARR_API_KEY", sonarr_cfg, "arr_xml", "Sonarr"),
        ])

        output_path = os.path.join(self.tmpdir, "export", "secrets.env")
        count = export_secrets_env(db_path, output_path)

        self.assertEqual(count, 1)
        lines = [l for l in Path(output_path).read_text().splitlines() if l]
        self.assertEqual(lines[0], "SONARR_API_KEY=xyz789abc123456b")

    def test_empty_result_no_file_written(self):
        from src.path_discovery import export_secrets_env

        db_path = self._make_db([])
        output_path = os.path.join(self.tmpdir, "export", "secrets.env")
        count = export_secrets_env(db_path, output_path)

        self.assertEqual(count, 0)
        self.assertFalse(os.path.exists(output_path))

    def test_value_with_special_chars_is_quoted(self):
        from src.path_discovery import export_secrets_env, _shell_quote_value

        self.assertEqual(_shell_quote_value("simple"), "simple")
        self.assertEqual(_shell_quote_value("has space"), "'has space'")
        self.assertEqual(_shell_quote_value("it's"), "'it'\\''s'")


class TestIsBackupDir(unittest.TestCase):
    def test_backup_dir_detection(self):
        from src.path_discovery import _is_backup_dir

        self.assertTrue(_is_backup_dir("prowlarr-config-backup"))
        self.assertTrue(_is_backup_dir("sonarr-bak"))
        self.assertTrue(_is_backup_dir("radarr-old"))
        self.assertTrue(_is_backup_dir("config-backup"))
        self.assertTrue(_is_backup_dir("backup"))
        self.assertTrue(_is_backup_dir("BACKUP"))  # case-insensitive
        self.assertFalse(_is_backup_dir("prowlarr"))
        self.assertFalse(_is_backup_dir("sonarr"))
        self.assertFalse(_is_backup_dir("overseerr"))


if __name__ == "__main__":
    unittest.main()

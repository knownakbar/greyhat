import json
import unittest
from datetime import date, timedelta
from pathlib import Path
import tempfile

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from automation.scope import load_scope, Scope, Target, ScopeError, AuthorizationExpired


def _write_scope(tmpdir, **overrides):
    data = {
        "engagement_id": "test-eng",
        "authorized_by": "tester",
        "start_date": "2000-01-01",
        "end_date": "2999-01-01",
        "targets": [{"host": "10.0.0.0/24", "description": "lab net"},
                    {"host": "*.internal.test"}],
    }
    data.update(overrides)
    path = Path(tmpdir) / "scope.json"
    path.write_text(json.dumps(data))
    return path


class TestTargetMatching(unittest.TestCase):
    def test_cidr_match(self):
        t = Target(host="10.0.0.0/24")
        self.assertTrue(t.matches("10.0.0.5"))
        self.assertFalse(t.matches("10.0.1.5"))

    def test_wildcard_hostname_match(self):
        t = Target(host="*.internal.test")
        self.assertTrue(t.matches("db.internal.test"))
        self.assertFalse(t.matches("db.external.test"))

    def test_exact_ip(self):
        t = Target(host="127.0.0.1")
        self.assertTrue(t.matches("127.0.0.1"))
        self.assertFalse(t.matches("127.0.0.2"))


class TestScopeLoading(unittest.TestCase):
    def test_load_valid_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(tmp)
            scope = load_scope(path)
            self.assertEqual(scope.engagement_id, "test-eng")
            self.assertEqual(len(scope.targets), 2)

    def test_missing_file(self):
        with self.assertRaises(ScopeError):
            load_scope("/nonexistent/path/scope.json")

    def test_empty_targets_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(tmp, targets=[])
            with self.assertRaises(ScopeError):
                load_scope(path)

    def test_missing_required_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = {"engagement_id": "x"}
            path = Path(tmp) / "scope.json"
            path.write_text(json.dumps(data))
            with self.assertRaises(ScopeError):
                load_scope(path)


class TestAuthorizationWindow(unittest.TestCase):
    def test_expired_window_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(
                tmp,
                start_date="2000-01-01",
                end_date="2000-01-02",
            )
            scope = load_scope(path)
            self.assertFalse(scope.is_within_window())
            with self.assertRaises(AuthorizationExpired):
                scope.require_active()

    def test_future_window_blocks(self):
        future = (date.today() + timedelta(days=30)).isoformat()
        far_future = (date.today() + timedelta(days=60)).isoformat()
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(tmp, start_date=future, end_date=far_future)
            scope = load_scope(path)
            self.assertFalse(scope.is_within_window())

    def test_active_window_allows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(tmp)
            scope = load_scope(path)
            self.assertTrue(scope.is_within_window())
            scope.require_active()  # should not raise


class TestHostAuthorization(unittest.TestCase):
    def test_only_scoped_hosts_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(tmp)
            scope = load_scope(path)
            self.assertTrue(scope.is_host_authorized("10.0.0.7"))
            self.assertTrue(scope.is_host_authorized("api.internal.test"))
            self.assertFalse(scope.is_host_authorized("evil.example.com"))
            self.assertFalse(scope.is_host_authorized("8.8.8.8"))

    def test_filter_authorized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_scope(tmp)
            scope = load_scope(path)
            hosts = ["10.0.0.7", "8.8.8.8", "api.internal.test", "evil.com"]
            self.assertEqual(
                scope.filter_authorized(hosts),
                ["10.0.0.7", "api.internal.test"],
            )


if __name__ == "__main__":
    unittest.main()

"""Host archive and network refusal controls, without a model or network call."""
import copy
import importlib.util
import io
from pathlib import Path
import signal
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

_spec = importlib.util.spec_from_file_location("consumer", Path(__file__).with_name("consumer.py"))
consumer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(consumer)


class Response:
    def __init__(self, raw=b"native", url="https://example.invalid/packet.zip", slow=False):
        self.stream = io.BytesIO(raw)
        self.url = url
        self.slow = slow

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, count):
        if self.slow:
            time.sleep(1)
        return self.stream.read(count)


class HostBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.selected = copy.deepcopy(consumer.selection())
        self.selected["archive"].update(bytes=6, sha256=consumer.sha(b"native"),
                                        url="https://example.invalid/packet.zip")
        self.select = patch.object(consumer, "selection", return_value=self.selected)
        self.select.start()

    def tearDown(self):
        self.select.stop()
        self.temporary.cleanup()

    def download(self, response):
        output = self.root / "packet.zip"
        with patch.object(consumer.urllib.request, "urlopen", return_value=response):
            consumer.download(output)
        return output

    def test_download_commits_only_exact_authenticated_bytes(self):
        self.assertEqual(self.download(Response()).read_bytes(), b"native")

    def test_short_extra_changed_and_non_https_downloads_leave_no_partial_file(self):
        for response in (Response(b"short"), Response(b"native-extra"), Response(b"mutate"),
                         Response(url="http://example.invalid/packet.zip")):
            with self.subTest(response=response), self.assertRaises(ValueError):
                self.download(response)
            self.assertFalse((self.root / "packet.zip").exists())

    def test_initial_url_requires_https_and_existing_output_is_preserved(self):
        self.selected["archive"]["url"] = "http://example.invalid/packet.zip"
        with self.assertRaises(ValueError):
            self.download(Response())
        output = self.root / "packet.zip"
        output.write_bytes(b"existing")
        with self.assertRaises(ValueError):
            self.download(Response())
        self.assertEqual(output.read_bytes(), b"existing")

    def test_a_blocked_read_obeys_the_hard_overall_deadline(self):
        set_timer = signal.setitimer
        def accelerated(timer, seconds):
            return set_timer(timer, min(seconds, 0.05))
        started = time.monotonic()
        previous = signal.getsignal(signal.SIGALRM)
        with patch.object(consumer.signal, "setitimer", side_effect=accelerated):
            with self.assertRaises(TimeoutError):
                self.download(Response(slow=True))
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse((self.root / "packet.zip").exists())
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    def test_an_existing_host_alarm_is_preserved(self):
        previous = signal.getsignal(signal.SIGALRM)
        with patch.object(consumer.signal, "getitimer", return_value=(10.0, 0.0)):
            with self.assertRaises(ValueError):
                self.download(Response())
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    def archive(self, entries):
        output = self.root / "selected.zip"
        with zipfile.ZipFile(output, "w") as archive:
            for name, mode in entries:
                item = zipfile.ZipInfo(name)
                item.external_attr = mode << 16
                archive.writestr(item, b"native")
        self.selected["archive"].update(bytes=output.stat().st_size, sha256=consumer.sha(output.read_bytes()),
                                        memberCount=len(entries), expandedBytes=6 * len(entries))
        return output

    def test_owner_selected_archive_still_refuses_unsafe_members(self):
        for entry in (("../escape", stat.S_IFREG), ("/escape", stat.S_IFREG),
                      ("safe/../escape", stat.S_IFREG), ("safe\\escape", stat.S_IFREG),
                      ("link", stat.S_IFLNK), ("pipe", stat.S_IFIFO), ("directory/", stat.S_IFDIR)):
            with self.subTest(entry=entry):
                archive = self.archive([entry])
                target = self.root / "target"
                target.mkdir(exist_ok=True)
                with self.assertRaises(ValueError):
                    consumer.unpack(archive, target)
                self.assertEqual(list(target.iterdir()), [])

    def test_duplicate_members_and_wrong_population_are_refused(self):
        archive = self.archive([("same", stat.S_IFREG), ("same", stat.S_IFREG)])
        with self.assertRaises(ValueError):
            consumer.unpack(archive, self.root / "target")
        archive = self.archive([("safe", stat.S_IFREG)])
        self.selected["archive"]["expandedBytes"] += 1
        with self.assertRaises(ValueError):
            consumer.unpack(archive, self.root / "target")

    def test_archive_selection_bounds_and_nonregular_files_are_refused(self):
        archive = self.archive([("safe", stat.S_IFREG)])
        self.selected["archive"]["bytes"] -= 1
        with self.assertRaises(ValueError):
            consumer.authenticate_archive(archive)
        link = self.root / "link.zip"
        link.symlink_to(archive)
        with self.assertRaises(ValueError):
            consumer.authenticate_archive(link)

    def test_safe_selected_archive_is_extracted(self):
        archive = self.archive([("safe/file.json", stat.S_IFREG)])
        target = self.root / "target"
        consumer.unpack(archive, target)
        self.assertEqual((target / "safe/file.json").read_bytes(), b"native")

    def test_path_replacement_after_authentication_cannot_change_extracted_bytes(self):
        archive = self.archive([("safe/file.json", stat.S_IFREG)])
        authenticate = consumer.authenticate_archive
        def replace_after_authentication(path):
            frozen = authenticate(path)
            path.write_bytes(b"candidate replaced the authenticated path")
            return frozen
        target = self.root / "target"
        with patch.object(consumer, "authenticate_archive", side_effect=replace_after_authentication):
            consumer.unpack(archive, target)
        self.assertEqual((target / "safe/file.json").read_bytes(), b"native")


if __name__ == "__main__":
    unittest.main()

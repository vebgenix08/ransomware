import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Windows PowerShell is required for the .bat demo")
class RandomFolderDemoTests(unittest.TestCase):
    def test_bat_wrapper_runs_the_random_activity_generator(self):
        project = Path(__file__).resolve().parents[1]
        batch = project / "scripts" / "demo_folder_activity.bat"
        with tempfile.TemporaryDirectory(prefix="ransomshield-demo-bat-") as temporary:
            watched = Path(temporary) / "watched"
            watched.mkdir()
            command = f"& '{batch}' -TargetPath '{watched}' -Scenario create-modify -NoPrompts"
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-Command", command],
                input="\r\n", capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Random activity is complete.", result.stdout)
            self.assertEqual(len(list(watched.glob("RansomShield-Random-Demo-*"))), 1)

    def test_each_demo_case_runs_only_inside_its_new_folder(self):
        project = Path(__file__).resolve().parents[1]
        script = project / "scripts" / "demo_folder_activity.ps1"
        with tempfile.TemporaryDirectory(prefix="ransomshield-demo-cases-") as temporary:
            for scenario in ("create-modify", "delete-burst", "mixed-burst"):
                watched = Path(temporary) / scenario
                watched.mkdir()
                result = subprocess.run(
                    [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                     "-TargetPath", str(watched), "-Scenario", scenario, "-NoPrompts"],
                    capture_output=True, text=True, timeout=90, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"Random case: {scenario}", result.stdout)
                demo_folders = list(watched.glob("RansomShield-Random-Demo-*"))
                self.assertEqual(len(demo_folders), 1)
                self.assertTrue(all(path.is_file() for path in demo_folders[0].iterdir()))

    def test_random_demo_uses_a_unique_safe_folder_and_varied_case(self):
        project = Path(__file__).resolve().parents[1]
        script = project / "scripts" / "demo_folder_activity.ps1"
        with tempfile.TemporaryDirectory(prefix="ransomshield-demo-test-") as temporary:
            watched = Path(temporary) / "watched"
            watched.mkdir()
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                 "-TargetPath", str(watched), "-NoPrompts"],
                capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Random activity test is ready.", result.stdout)
            self.assertIn("Random case:", result.stdout)
            demo_folders = list(watched.glob("RansomShield-Random-Demo-*"))
            self.assertEqual(len(demo_folders), 1)
            self.assertRegex(result.stdout, r"Random case: (create-modify|delete-burst|mixed-burst)")
            self.assertTrue(all(path.is_file() for path in demo_folders[0].iterdir()))

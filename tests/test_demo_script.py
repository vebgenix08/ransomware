import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Windows PowerShell is required for the .bat demo")
class RandomFolderDemoTests(unittest.TestCase):
    def test_guided_demo_runs_six_distinct_steps_in_a_new_folder(self):
        project = Path(__file__).resolve().parents[1]
        script = project / "scripts" / "demo_folder_activity.ps1"
        with tempfile.TemporaryDirectory(prefix="ransomshield-guided-demo-") as temporary:
            watched = Path(temporary) / "watched"
            watched.mkdir()
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                 "-TargetPath", str(watched), "-Scenario", "guided", "-NoPrompts"],
                capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for step in (
                "STEP 1/6: Create only",
                "STEP 2/6: Modify a few",
                "STEP 3/6: Modify more",
                "STEP 4/6: Create again",
                "STEP 5/6: Delete some",
                "STEP 6/6: Mix create, modify, and delete",
            ):
                self.assertIn(step, result.stdout)
            demo_folders = list(watched.glob("RansomShield-Guided-Demo-*"))
            self.assertEqual(len(demo_folders), 1)
            self.assertIn("Six-step walkthrough complete.", result.stdout)

    def test_bat_wrapper_runs_the_six_step_walkthrough_by_default(self):
        project = Path(__file__).resolve().parents[1]
        batch = project / "scripts" / "demo_folder_activity.bat"
        with tempfile.TemporaryDirectory(prefix="ransomshield-demo-bat-") as temporary:
            watched = Path(temporary) / "watched"
            watched.mkdir()
            command = f"& '{batch}' -TargetPath '{watched}' -NoPrompts"
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-Command", command],
                input="\r\n", capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Six-step walkthrough complete.", result.stdout)
            self.assertEqual(len(list(watched.glob("RansomShield-Guided-Demo-*"))), 1)

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
                 "-TargetPath", str(watched), "-Scenario", "random", "-NoPrompts"],
                capture_output=True, text=True, timeout=90, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Random activity test is ready.", result.stdout)
            self.assertIn("Random case:", result.stdout)
            demo_folders = list(watched.glob("RansomShield-Random-Demo-*"))
            self.assertEqual(len(demo_folders), 1)
            self.assertRegex(result.stdout, r"Random case: (create-modify|delete-burst|mixed-burst)")
            self.assertTrue(all(path.is_file() for path in demo_folders[0].iterdir()))

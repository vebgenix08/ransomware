import os
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell")


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "Windows PowerShell is required for the .bat demo")
class RandomFolderDemoTests(unittest.TestCase):
    def test_runtime_app_settings_override_env_defaults_for_path_and_thresholds(self):
        project = Path(__file__).resolve().parents[1]
        script = project / "scripts" / "demo_folder_activity.ps1"
        with tempfile.TemporaryDirectory(prefix="ransomshield-runtime-settings-") as temporary:
            root = Path(temporary)
            watched = root / "effective-watched-folder"
            watched.mkdir()
            policy_path = root / "effective-policy.json"
            policy = {"window_seconds": 17, "delete_threshold": 3, "modify_threshold": 2,
                      "mixed_threshold": 7, "mixed_destructive_minimum": 2, "auto_quarantine": True}
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            runtime_path = root / "runtime.json"
            runtime_path.write_text(json.dumps({
                "target_path": str(watched), "policy_path": str(policy_path), "policy": policy,
                "auto_quarantine": True, "quarantine_mode": "dry-run",
            }), encoding="utf-8")
            environment = os.environ.copy()
            environment["MONITOR_RUNTIME_SETTINGS_PATH"] = str(runtime_path)
            environment["MONITOR_TARGET_PATH"] = str(root / "wrong-env-folder")
            environment["MONITOR_POLICY_PATH"] = str(root / "wrong-env-policy.json")
            result = subprocess.run(
                [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
                 "-Scenario", "delete-burst", "-NoPrompts"],
                capture_output=True, text=True, timeout=90, check=False, env=environment,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"Watched folder: {watched}", result.stdout)
            self.assertIn("Alert window: 17 seconds", result.stdout)
            self.assertIn("Limits: delete 3, modify 2, mixed 7, minimum modified/deleted 2", result.stdout)
            self.assertIn("Settings source: effective application settings", result.stdout)
            self.assertIn("Automatic quarantine mode: dry-run", result.stdout)

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
            demo_folders = list(watched.glob("RS-G-*"))
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
            self.assertEqual(len(list(watched.glob("RS-G-*"))), 1)

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
                demo_folders = list(watched.glob("RS-R-*"))
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
            demo_folders = list(watched.glob("RS-R-*"))
            self.assertEqual(len(demo_folders), 1)
            self.assertRegex(result.stdout, r"Random case: (create-modify|delete-burst|mixed-burst)")
            self.assertTrue(all(path.is_file() for path in demo_folders[0].iterdir()))

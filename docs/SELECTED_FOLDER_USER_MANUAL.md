# User Manual: Selected-Folder Quarantine

This guide shows how to watch a folder on your computer, move a file into quarantine, and restore it. Start with a **temporary test folder** containing only files you can replace.

## What quarantine does

Quarantine moves a file out of the folder being watched so it is separated from normal files. For a folder selected in the browser, the file stays on your computer. RansomShield creates a `RansomShield Quarantine` folder inside the selected folder and stores the file there. It does not upload the file.

Selected-folder quarantine is **manual**: you choose each file to move. Automatic quarantine is available only for the app server folder.

## Before you begin

- Use a recent **Chrome or Edge** browser.
- Open RansomShield through `http://localhost:5000` or an HTTPS address and sign in.
- Keep the RansomShield page open while watching the folder.
- Use a test folder first. Do not test with important files.

## 1. Select and watch a folder

1. Open **Dashboard → Monitor files**.
2. Under **Watch a folder on this device**, select **Choose folder**.
3. Choose the folder you want RansomShield to watch.
4. When the browser asks, allow **read and write** access. Read access lets RansomShield see file changes. Write access is needed to move files into quarantine and restore them.
5. Check that the page says **Watching in this browser** and shows the folder name.

The first scan is a starting point. It does not report the files already in the folder as new. The browser checks for changes about every five seconds.

## 2. Create an alert using test files

An alert appears only when file changes reach the limits in **Alert limits and quarantine** during the selected time window. The default limits are:

| Rule | Default limit |
| --- | ---: |
| Changed files deleted | 10 |
| Different files modified | 20 |
| Total different files changed | 30, including at least 10 modified or deleted |
| Time window | 30 seconds |

For a safe test, use a temporary folder and make changes to several disposable files quickly. You can temporarily lower the limits in **Monitor files** to make a small test easier. Restore your usual limits afterward.

## 3. Quarantine a file

1. Open **Dashboard → Alerts**.
2. Open **Changed files** for the alert.
3. Find a **created** or **modified** file from the selected folder.
4. Select **Quarantine in selected folder**.
5. Check the source and destination in the confirmation message. Select **OK** only if the path is correct; choose **Cancel** to leave the file in place.

RansomShield copies the file into quarantine, checks that its size and SHA-256 hash match, then removes the original from the watched folder. The alert will not offer quarantine for deleted files because they are already gone.

The browser method supports files up to **100 MB**. The selected folder must be the same folder that produced the alert, and it must still be selected and watching. If you stop watching or close the page, select the folder again before using an alert action.

## 4. Restore a quarantined file

1. Go to **Dashboard → Monitor files**.
2. If the folder is not selected, choose the same folder again and allow read/write access.
3. Under **Quarantined in this selected folder**, find the file.
4. Select **Restore file**, check the displayed restore path, then select **OK** to continue or **Cancel** to stop.

RansomShield checks the file hash before restoring. It will not overwrite a file that already exists at the original location. Move or rename the existing file first, then try again. The quarantine record remains in `RansomShield Quarantine/manifest.json` inside the selected folder.

## Where is the file stored?

For example, if you select `C:\Users\You\Documents\TestFolder`, the quarantined file is stored under:

```text
C:\Users\You\Documents\TestFolder\RansomShield Quarantine\<record-id>\payload
```

Keep the `RansomShield Quarantine` folder and its `manifest.json` file. They are needed to restore files and show the quarantine history when you select this folder again.

## Important limits

- Quarantine is a file-move feature, not proof that a file is infected.
- Use a test folder first. A low alert limit can flag normal work.
- Selected-folder quarantine is manual. It does not automatically move files.
- Deleted files cannot be quarantined or restored by this feature.
- If read/write access is denied, choose the folder again and allow it. Without that permission, monitoring or file movement may not work.
- The browser sends file paths and basic change details to RansomShield, but not the file contents.
- This is a project prototype. Do not rely on it as your only backup or security tool.

For the app server folder and Windows endpoint agent, see [the main project guide](../README.md) and [the endpoint-agent guide](WINDOWS_ENDPOINT_AGENT.md).

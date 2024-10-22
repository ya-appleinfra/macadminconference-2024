# MacOS Healing Tool

> One script to heal them all

This is a [py2app](https://py2app.readthedocs.io/en/latest/) application you can use to fix some common macOS problems. Follow this [insructions](#how-to-build) to build and run it.

> NOTE: this tool heavily depends on Yandex Popup that can be found [here](https://github.com/ya-appleinfra/yandex-popup)

These problems are detected by the app and fixed automatically:

- Missing MDM profile
- Disabled Filevault
- Unescrowed bootstrap token
- FindMy turned on

These problems cannot be detected automatically and need a [trigger](##triggers) to fix them:

- Invalid FileVault personal key
- Invalid MDM profile

## How to build

1. Install [Python 3 v3.10.11](https://www.python.org/ftp/python/3.10.11/python-3.10.11-macos11.pkg). Important — it should be universal so you can build a universal application that will work on both ARM and x64 Macs
2. Install py2app v0.27 — `python3 -m pip install py2app==0.27`
3. Сhange the variables in `setup.py` to your environment and taste
4. Specify certData in `py2app.sh` if you have a certificate you want to sign the app with
5. Run `/bin/bash ${path_to_macos_healing_tool_folder}/py2app.sh`
6. Get the сompiled application in the `dist` folder

## Triggers

Some of the healing steps can't be detected automatically on the Mac itself and you should trigger them manually. There are two ways to do this — specify them in the `TRIGGER_STEPS` variable in `script.py` or put the JSON file in the path specified in `TRIGGER_FILE` variable. File has a higher priority so if it will be found it will override the `TRIGGER_STEPS` variable. File should look like this:

```json
{
    "remove_mdm_profile": true,
    "mdm_profile": false
}
```

Where `remove_mdm_profile` and `mdm_profile` are the steps you want to trigger.
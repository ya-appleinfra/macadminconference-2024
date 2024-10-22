#!/bin/bash

scriptPath=$(realpath "${0}")
scriptFolder=$(dirname "${scriptPath}")
cd "${scriptFolder}"
python3 ./setup.py py2app --arch universal2

# Uncomment and fill your data to sign the application
# certData = "Developer ID Application: Company LLC (LO7L2K86EK)"
# codesign --force --deep --sign \
#     "${certData}" \
#     ./dist/MacosHealingTool.app

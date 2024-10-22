# pylint: disable=missing-docstring

from setuptools import setup

from script import __version__ as VERSION

setup(
    author='Apple Infrastructure team',
    name='MacosHealingTool',
    version=VERSION,
    app=['script.py'],
    options={'py2app': {'iconfile': 'icons/security_icon.png'}},
    data_files=[('icons')],
    setup_requires=['py2app==0.27']
)

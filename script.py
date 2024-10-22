# -*- coding: utf-8 -*-

__version__ = '0.1'

import os
import pwd
import sys
import time
import json
import logging
import threading
import subprocess

from os import environ as env
from pipes import quote
from xml.sax.saxutils import escape as xml_escape

#######################################################################
################################################ CUSTOMIZABLE VARIABLES
#######################################################################

# Path to the BINARY inside an app bundle.
YA_POPUP_PATH='/Library/Application Support/Yandex Popup/Yandex Popup.app/Contents/MacOS/Yandex Popup'
# What the user should do when problems occur, starting with a lowercase letter.
ACTION_FOR_ASSISTANCE = "contact Service Desk"
# Your MDM enrollment page URL
MDM_ENROLL_URL = "https://your.mdm.com/enroll"
# Instructions to show before enrolment process. Just to make sure if user is prepared.
PRE_ENROLLMENT_INSTRUCTIONS = "Now we're going to open enrollment page where you'll need to download and then install the enrollment profile."
# Window with this text will be shown during the enrollment process and here you can place detailed instructions.
ENROLLMENT_INSTRUCTIONS = "Please click the \"Enroll\" button on the opened page and install it in the opened System Preferences window."

# There are two problems that are difficult to detect localy and easier
# to find with the help of MDM solutions. Here you can manually trigger
# the fixes for those issues or specify a path to the json file,
# containing the same variables and values. The file has a higher
# priority.
TRIGGER_STEPS = {
    'remove_mdm_profile': False,
    'fv2_reissue': False
}
TRIGGER_FILE = '/tmp/trigger_steps.json'

#######################################################################
########### USUALLY THERE IS NO NEED TO CHANGE ANYTHING BELOW THIS MARK
#######################################################################

logging.basicConfig(filename='/tmp/macoshealingtool.log', level = logging.DEBUG)
log = logging.getLogger(__name__)

POPUP_PID_FILE   = '/tmp/popup.pid'
ICONS_DIR = '{}/icons'.format(os.getcwd())


MDM_ENROLLED_PATTERN = 'mdm enrollment: yes'
BOOTSTRAP_ALLOWED_PATTERN = 'bootstrap token supported on server: yes'
BOOTSTRAP_ESCROWED_PATTERN = 'bootstrap token escrowed to server: yes'
FV2_ENABLED_PATTERN = 'filevault is on'

CHECK_STEPS = [
    'remove_mdm_profile',
    'mdm_profile',
    'fv2_enabled',
    'fv2_reissue',
    'bootstrap',
    'find_my_mac'
]

try:
    with open(TRIGGER_FILE, 'r') as f:
        TRIGGER_STEPS_CHECK = json.load(f)
        for trigger in TRIGGER_STEPS:
            if  trigger not in TRIGGER_STEPS_CHECK.keys():
                continue
            if TRIGGER_STEPS_CHECK[trigger] is not bool:
                continue
            TRIGGER_STEPS[trigger] = TRIGGER_STEPS_CHECK[trigger]
except FileNotFoundError:
    pass

TRIGGERED_STEPS = [key for key, value in TRIGGER_STEPS.items() if value == True]

DEFAULT_STEPS = [
    'mdm_profile',
    'fv2_enabled',
    'bootstrap',
    'find_my_mac'
]

STEPS_DESC_MAP = {
    'remove_mdm_profile' : 'MDM Profile reinstall',
    'mdm_profile' : 'MDM Profile enrollment',
    'fv2_enabled' : 'FileVault2',
    'fv2_reissue' : 'FV2 key reissue',
    'bootstrap'   : 'Bootstrap token escrow',
    'find_my_mac' : 'Find My Mac deactivation'
}

STEPS_PROBLEM_MAP = {
    'remove_mdm_profile' : 'MDM Profile issue',
    'mdm_profile' : 'No MDM Profile installed',
    'fv2_enabled' : 'Full disk encryption not applied',
    'fv2_reissue' : 'FV2 key needs to be reissued',
    'bootstrap'   : 'Bootstrap token escrow needed',
    'find_my_mac' : 'Find My Mac deactivation needed'
}

STEPS_DONE_MAP = {
    'remove_mdm_profile' : 'MDM Profile was fixed',
    'mdm_profile' : 'MDM Profile was installed',
    'fv2_enabled' : 'Full disk encryption was applied',
    'fv2_reissue' : 'FV2 key was reissued',
    'bootstrap'   : 'Bootstrap token was escrowed',
    'find_my_mac' : 'Find My Mac was deactivated'
}

progress_popup_kwargs = {
        'pid-file'      : POPUP_PID_FILE,
        'popup-type'    : 'progress',
        'progress-type' : 'spinner',
        'header-text'   : 'Setting things up...',
        'ok-button'     : 0,
        'action-button' : 0
    }

# -- generic

def demote(user_uid, user_gid):
    """Pass the function 'set_ids' to preexec_fn, rather than just calling
    setuid and setgid. This will change the ids for that subprocess only"""

    def set_ids():
        os.setgid(user_gid)
        os.setuid(user_uid)

    return set_ids


def yandex_popup(options={}, background=False):

    console_user = get_console_user()
    user_pwnam = pwd.getpwnam(console_user)

    run_command('rm -f {} || true'.format(POPUP_PID_FILE), shell=True)

    kdefaults = {
                'popup-type': 'message',

                # windows
                'window-all-spaces' : 1,
                'window-controls': 0,
                'window-title': 0,
                'window-floating': 1,
                'window-position': 'center',
                'ok-button' : 1,
                'ok-button-text' : 'Go on',
                'action-button' : 1,
                'action-button-text' : 'Cancel',
                'action-button-actions' : 'exit_err'

            }

    kdefaults.update(**options)

    popup_args = [YA_POPUP_PATH]

    for item in kdefaults:
        arg_item = item.replace('_', '-')
        popup_args.append('--{}={}'.format(arg_item, kdefaults[item]))

    log.debug(popup_args)

    process = subprocess.Popen(popup_args,
                               preexec_fn=demote(user_pwnam.pw_uid, user_pwnam.pw_gid),
                               shell=False,
                               stdin=subprocess.PIPE,
                               stdout = subprocess.PIPE,
                               stderr = subprocess.PIPE)

    if not background:
        returncode = process.wait()

        stdout = process.stdout.read()
        stderr = process.stderr.read()

        log.debug("code: {},{},".format(returncode, stderr))

        ret = stdout

        if kdefaults['popup-type'] == 'input' and returncode == 0:
            ret = json.loads(stdout)

        return (returncode, ret, stderr)
    else:
        return (process)


def yandex_popup_wait_pidfile():
    log.debug('waiting for popup pid file')
    while not os.path.exists(POPUP_PID_FILE):
        time.sleep(1)
    log.debug('popup pid file appeared')


def yandex_popup_kill():
    log.debug('trying to kill popup')
    if not os.path.exists(POPUP_PID_FILE):
        log.warn('pidfile not found(')
    else:
        with open(POPUP_PID_FILE, 'r') as f:
            popup_pid = f.read().rstrip('\n')
        code, out, err = run_command('kill {}'.format(popup_pid), shell=True)
        code, out, err = run_command('rm -f {} || true'.format(POPUP_PID_FILE), shell = True)


def run_command(command, shell=True, stdin_data=None):

    if stdin_data is None:
        p = subprocess.Popen(command, shell = shell, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        returncode = p.wait()
        return (returncode, p.stdout.read().decode('utf-8').rstrip('\n'), p.stderr.read().decode('utf-8').rstrip('\n'))

    p = subprocess.Popen(command, shell = shell, stdout = subprocess.PIPE, stderr = subprocess.PIPE, stdin = subprocess.PIPE)

    out = p.communicate(input=stdin_data.encode('utf-8'))

    returncode = p.wait()

    return (returncode, out[0].decode('utf-8').rstrip('\n'), out[1].decode('utf-8').rstrip('\n'))



# -- user interaction related

def greetings(needed_steps=None):

    if needed_steps is not None and len(needed_steps) > 0:
        fixes_msg = 'The following issues were found:\n\n  ⚠️ ' + '\n  ⚠️ '.join( [STEPS_PROBLEM_MAP[x] for x in  needed_steps] )
    else:
        fixes_msg = 'Follow a few simple steps to ensure that security of your Mac is in proper condition'

    code, stdout, stderr = yandex_popup({

            'icon-name': 'NSSecurity',
            'header-text' : 'Improve security of your Mac',
            'description-text' : fixes_msg,
            'ok-button' : 1,
            'ok-button-text' : 'Continue',
            'action-button' : 1,
            'action-button-text' : 'Cancel',
            'action-button-actions' : 'exit_err'
        })

    if code != 0:
        log.info('User aborted, exiting')
        sys.exit(0)


def finish(failed_steps=[], success_steps=[], header_text = None):

    main_message=""
    header = 'Success'
    icon_path = '{}/ToolbarFavoritesIcon.icns'.format(ICONS_DIR)
    ok_text = 'Finish'

    if success_steps:
        main_message += '\nFollowing issues were fixed:\n\n  ✅ ' + '\n  ✅ '.join( [STEPS_DONE_MAP[x] for x in success_steps] )

    if failed_steps:
        if success_steps:
            main_message += '\n\n'
        main_message += 'Some issues are still there: \n\n  🛑 ' + '\n  🛑 '.join( [STEPS_PROBLEM_MAP[x] for x in failed_steps] )
        main_message += '\n\n Please, {} for assistance'.format(ACTION_FOR_ASSISTANCE)
        header = 'Not yet secured'
        icon_path = '{}/ToolbarDeleteIcon.icns'.format(ICONS_DIR)
        ok_text = 'Okay :('

    if main_message == "":
        main_message = 'Your Mac is well secured now'

    if header_text is not None:
        header = header_text

    yandex_popup({
        'icon-path' : icon_path,
        'icon-max-width' : 1,
        'header-text' : header,
        'description-text' : main_message,
        'action-button' : 0,
        'ok-button-text' : ok_text
    })

    sys.exit(0)


def ask_user_pass(username, first_try=True):
    options = {'icon-name': 'NSSecurity',
               'window-title': 0,
               'popup-type': 'input',
               'action-button': 1,
               'action-button-actions': 'exit_err',
               'action-button-text': 'Cancel',
               'input-secure': 1,
               'header-text': 'We need your password',
               'description-text': 'Enter your password in the field below, so we can set up everything for your Mac' if first_try else 'Wrong password supplied, please try one more time'
    }
    # input_json = yandex_popup(options)

    code, input_json, stderr = yandex_popup(options)

    if code == 0:
        return input_json['input']

    return None


def get_user_auth(user_login):

    PASSWORD_VALID = False
    first_try = True

    while not PASSWORD_VALID:

        user_password = ask_user_pass(user_login, first_try=first_try)

        if user_password is None:
            log.info('User aborted on password query')
            return user_password

        if valid_user_password(user_login, user_password):
            log.info('Valid user password granted')
            PASSWORD_VALID = True

        else:
            log.info('Invalid password provided')

        first_try = False

    return user_password


def valid_user_password(user_login, user_password):

    code, out, err = run_command('/usr/bin/dscl /Search -authonly "{}" {}'.format(user_login, quote(user_password)), shell = True)

    if code == 0:
        return True

    return False


def get_console_user():

    code, out, err = run_command("stat -f '%Su' /dev/console", shell = True)

    if code != 0:
        log.error('failed to determine current active account: {}, {}, {}'.format(code, out, err))
        return False

    user_login = out

    return user_login


# -- check logic

def password_needed(RUN_STEPS, user_login):

    if 'fv2_reissue' in RUN_STEPS:
        return True

    if 'bootstrap' in RUN_STEPS and not bootstrap_escrowed() and bootstrap_allowed():
        return True

    if 'fv2_enabled' in RUN_STEPS and not fv2_enabled():
        return True

    return False


# -- -- MDM Profile

def remove_mdm_profile():

    log.info('starting mdm profile removal')

    # finding mdm profile identifier

    code, out, err = run_command("profiles -Lv | grep 'name: MDM Profile' -4 | awk -F': ' '/attribute: profileIdentifier/{print $NF}'")

    if code != 0:
        log.error('failed while looking for mdm profile')
        return False

    mdm_profile_identifier = out

    if len(mdm_profile_identifier) == 0:
        log.error('no mdm profile found')
        return False

    code, out, err = run_command("profiles remove -identifier {}".format(mdm_profile_identifier))

    if code != 0:
        log.error('failed to remove mdm profile')
        return False

    return True


def mdm_enrolled():

    log.info('checking if mdm profile installed...')

    code, out, err = run_command('profiles status -type enrollment', shell = True)

    if code != 0:
        log.error('error requesting enrollment status: {}'.format(err))
        return False

    if MDM_ENROLLED_PATTERN in out.lower():
        log.info('mdm profile is OK')
        return True

    log.info('looks like mdm profile is not installed')

    return False


def enroll_mdm_profile(user):

    MDM_INSTALLED = False

    code, out, err = run_command('open {}'.format(MDM_ENROLL_URL))

    code, out, err = run_command('open /System/Library/PreferencePanes/Profiles.prefPane', shell = True)

    # POPUP

    popup_kwargs = progress_popup_kwargs.copy()

    popup_kwargs['icon-path'] = '{}/prefs_icon.png'.format(ICONS_DIR)
    popup_kwargs['window-position'] = 'left-bottom'
    popup_kwargs['window-height'] = '300'
    popup_kwargs['window-width'] = '500'
    popup_kwargs['progress-type'] = 'bar'
    popup_kwargs['header-text'] = 'Install MDM Profile'
    popup_kwargs['description-text'] = ENROLLMENT_INSTRUCTIONS


    enroll_popup_thread = threading.Thread(target = yandex_popup, kwargs = {'options': popup_kwargs})
    enroll_popup_thread.daemon = True
    enroll_popup_thread.start()

    yandex_popup_wait_pidfile()


    if not MDM_INSTALLED:

        user_downloads_dir = '/Users/{}/Downloads'.format(user)

        user_downloads_dir_contents = set( os.listdir(user_downloads_dir) )

        while not MDM_INSTALLED:

            new_user_downloads_dir_contents = set( os.listdir(user_downloads_dir) )

            if len( new_user_downloads_dir_contents - user_downloads_dir_contents ) > 0:
                code, out, err = run_command('open /System/Library/PreferencePanes/Profiles.prefPane', shell = True)
                user_downloads_dir_contents = new_user_downloads_dir_contents

            time.sleep(2)

            if mdm_enrolled():
                MDM_INSTALLED = True
                log.info('mdm installed')

                yandex_popup_kill()

                return True

            else:

                log.info('waiting for mdm install')


# -- -- Bootstrap tokens

def bootstrap_allowed():

    log.info('checking if bootstrap allowed...')

    code, out, err = run_command('profiles status -type bootstraptoken', shell = True)

    if code != 0:
        log.error('error requesting bootstrap token status: {}'.format(err))
        return False

    if BOOTSTRAP_ALLOWED_PATTERN in out.lower():
        log.info('bootstrap allowance is OK')
        return True

    return False


def bootstrap_escrowed():

    if not bootstrap_allowed():
        return False

    log.info('checking if bootstrap escrowed...')

    code, out, err = run_command('profiles status -type bootstraptoken', shell = True)

    if code != 0:
        log.error('error requesting bootstrap token status: {}'.format(err))
        return False

    if BOOTSTRAP_ESCROWED_PATTERN in out.lower():
        log.info('bootstrap escrowed, OK')
        return True

    return False


def escrow_bootstrap(user_login, user_password):

    # POPUP

    popup_kwargs = progress_popup_kwargs.copy()

    popup_kwargs['window-position'] = 'center'
    popup_kwargs['icon-name'] = 'NSSecurity'
    popup_kwargs['progress-type'] = 'progress'
    popup_kwargs['header-text'] = 'Escrowing bootstrap token...'
    popup_kwargs['description-text'] = 'Please, wait a few moments...'


    popup_thread = threading.Thread(target = yandex_popup, kwargs = {'options': popup_kwargs})
    popup_thread.daemon = True
    popup_thread.start()

    yandex_popup_wait_pidfile()


    # invoking profiles

    code, out, err = run_command('profiles install -type bootstraptoken -user {} -password {}'.format(user_login, quote(user_password)), shell = True)

    yandex_popup_kill()

    if code != 0:
        log.error('error escrowing bootstrap token: {}, {}, {}'.format(code, out, err))
        return False

    return True


# -- -- FV2 enabled

def fv2_enabled():

    code, out, err = run_command('fdesetup status', shell = True)

    if code != 0:
        log.error('error checkin fv2 status: {}'.format(err))
        return None

    if FV2_ENABLED_PATTERN in out.lower():
        return True

    return False


def enable_fv2(user_login, user_password):

    # POPUP

    popup_kwargs = progress_popup_kwargs.copy()

    popup_kwargs['window-position'] = 'center'
    popup_kwargs['icon-path'] = '{}/security_icon.png'.format(ICONS_DIR)
    popup_kwargs['progress-type'] = 'progress'
    popup_kwargs['header-text'] = 'Enabling FileVault2'
    popup_kwargs['description-text'] = 'Please, wait a few moments...'


    popup_thread = threading.Thread(target = yandex_popup, kwargs = {'options': popup_kwargs})
    popup_thread.daemon = True
    popup_thread.start()

    yandex_popup_wait_pidfile()

    # prepare xml password

    user_password_escaped = xml_escape(user_password)

    fdesetup_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Username</key>
    <string>{}</string>
    <key>Password</key>
    <string>{}</string>
</dict>
</plist>
""".format(user_login, user_password_escaped)

    # invoking fdesetup

    code, out, err = run_command('/usr/bin/fdesetup enable -inputplist', shell = True, stdin_data = fdesetup_plist)


    yandex_popup_kill()

    if code != 0:
        log.error('error enabling fv2:\n\ncode: {}\n\nstdout:\n{}\n\nstderr:\n{}'.format(code, out, err))
        return False

    log.info('successfuly enabled fv2')

    return True


def fv2_clean_users(user_login):

    code, out, err = run_command('/usr/bin/fdesetup list', shell = True)

    if code != 0:
        log.error('error checking fv2 users:\n\ncode: {}\n\nstdout:\n{}\n\nstderr:\n{}'.format(code, out, err))
        return False

    # POPUP

    popup_kwargs = progress_popup_kwargs.copy()

    popup_kwargs['window-position'] = 'center'
    popup_kwargs['icon-path'] = '{}/security_icon.png'.format(ICONS_DIR)
    popup_kwargs['progress-type'] = 'progress'
    popup_kwargs['header-text'] = 'Fixing FileVault2 users'
    popup_kwargs['description-text'] = 'Please, wait a few moments...'


    popup_thread = threading.Thread(target = yandex_popup, kwargs = {'options': popup_kwargs})
    popup_thread.daemon = True
    popup_thread.start()

    yandex_popup_wait_pidfile()


    user_lines = out.split('\n')
    fv2_users = [ x.split(',')[0] for x in user_lines ]

    users_to_remove = list( set(fv2_users) - set([user_login]) )

    for user in users_to_remove:

        log.info('removing user {} from fv2'.format(user))

        code, out, err = run_command('/usr/bin/fdesetup remove -user {}'.format(user), shell = True)

        if code != 0:
            log.error('error removing fv2 user: {} \n\ncode: {}\n\nstdout:\n{}\n\nstderr:\n{}'.format(user, code, out, err))

            yandex_popup_kill()
            return False

    yandex_popup_kill()
    return True


# -- -- FV2 reissue

def fv2_reissue(user_login, user_password):

    # POPUP

    popup_kwargs = progress_popup_kwargs.copy()

    popup_kwargs['window-position'] = 'center'
    popup_kwargs['icon-path'] = '{}/security_icon.png'.format(ICONS_DIR)
    popup_kwargs['progress-type'] = 'progress'
    popup_kwargs['header-text'] = 'Reissuing FileVault2 key...'
    popup_kwargs['description-text'] = 'Please, wait a few moments...'


    popup_thread = threading.Thread(target = yandex_popup, kwargs = {'options': popup_kwargs})
    popup_thread.daemon = True
    popup_thread.start()

    yandex_popup_wait_pidfile()


    # if needed, unload and kill FDERecoveryAgent

    code, out, err = run_command('/bin/launchctl list', shell = True)

    if code != 0:
        log.warning('error listing launchctl jobs: {}, {}'.format(out, err))

    if 'com.apple.security.FDERecoveryAgent' in out:
        code, out, err = run_command('/bin/launchctl unload /System/Library/LaunchDaemons/com.apple.security.FDERecoveryAgent.plist', shell = True)

        log.info('unloaded FDERecoveryAgent: {}, {}'.format(out, err))

    code, out, err = run_command('pgrep -q "FDERecoveryAgent"', shell = True)

    if code == 0:
        code, out, err = run_command('killall "FDERecoveryAgent"', shell = True)
        log.info('killed FDERecoveryAgent: {},{}'.format(out, err))

    # prepare xml password

    user_password_escaped = xml_escape(user_password)

    # log.debug('user_password escaped: {}'.format(user_password_escaped))

    fdesetup_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Username</key>
    <string>{}</string>
    <key>Password</key>
    <string>{}</string>
</dict>
</plist>
""".format(user_login, user_password_escaped)

    # invoking fdesetup

    code, out, err = run_command('/usr/bin/fdesetup changerecovery -norecoverykey -verbose -personal -inputplist', shell = True, stdin_data = fdesetup_plist)


    yandex_popup_kill()

    if code != 0:
        log.error('error reissuing fv2 key:\n\ncode: {}\n\nstdout:\n{}\n\nstderr:\n{}'.format(code, out, err))
        return False

    log.info('successfuly reissued fv2 key')

    return True

def fmm_enabled():
    code, out, err = run_command("defaults read /Library/Preferences/com.apple.FindMyMac.plist FMMEnabled", shell=True)
    return True if out == "1" else False

def fmm_disable(mdm_profile_installed = True):

    log.info('fmm deactivation started')

    code, os_version, err = run_command('sw_vers -productVersion', shell=True)

    log.debug('os version detected: {}'.format(os_version))

    osascript_ge_15_0 = """tell application "System Events"
        activate
        activate application "System Settings"
        repeat
            delay 0.3
            if button 1 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 1 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings"
        repeat
            delay 0.3
            if sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        repeat
            delay 0.3
            if button 1 of group 1 of scroll area 1 of group 1 of sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        set n to "Options for Find My Mac"
        set theButtons to (every button of group 1 of scroll area 1 of group 1 of sheet 1 of window 1 of application process "System Settings" whose value of attribute "AXAttributedDescription" is n)
        click item 1 of theButtons
        repeat
            delay 0.3
            if sheet 1 of sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 1 of sheet 1 of sheet 1 of window 1 of application process "System Settings"
        activate application "System Preferences"
        end tell"""

    osascript_ge_14_0 = """tell application "System Events"
        activate
        activate application "System Settings"
        repeat
            delay 0.3
            if button 5 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 5 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings"
        repeat
            delay 0.3
            if sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        repeat
            delay 0.3
            if button 1 of group 1 of scroll area 1 of group 1 of sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        set n to "Options for Find My Mac"
        set theButtons to (every button of group 1 of scroll area 1 of group 1 of sheet 1 of window 1 of application process "System Settings" whose value of attribute "AXAttributedDescription" is n)
        click item 1 of theButtons
        repeat
            delay 0.3
            if sheet 1 of sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 1 of sheet 1 of sheet 1 of window 1 of application process "System Settings"
        activate application "System Preferences"
        end tell"""

    osascript_ge_13_3 = """tell application "System Events"
        activate
        activate application "System Settings"
        repeat
            delay 0.3
            if button 5 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 5 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings"
        repeat
            delay 0.3
            if button 6 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 6 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings"
        repeat
            delay 0.3
            if sheet 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 1 of sheet 1 of window 1 of application process "System Settings"
        end tell"""

    osascript_ge_13_0 = """tell application "System Events"
        activate
        activate application "System Settings"
        repeat
            delay 0.3
            if button 5 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings" exists then exit repeat
        end repeat
        click button 5 of group 2 of scroll area 1 of group 1 of group 2 of splitter group 1 of group 1 of window 1 of application process "System Settings"
        repeat
        delay 0.3
            if sheet 1 of window 1 of application process "System Settings" exists then exit repeat
            end repeat
        click button 1 of sheet 1 of window 1 of application process "System Settings"
        end tell"""

    osascript_ge_11_0 = """tell application "System Events"
        activate
        activate application "System Preferences"
        repeat
            delay 0.3
            if group 1 of window 1 of application process "System Preferences" exists then exit repeat
        end repeat
        repeat
            delay 0.3
            if row 10 of table 1 of scroll area 1 of group 1 of window 1 of application process "System Preferences" exists then exit repeat
        end repeat
        repeat with aRow in every row of table 1 of scroll area 1 of group 1 of window 1 of application process "System Preferences"
	    if (value of static text 1 of UI element 1 of aRow = "Find My Mac") then
                click button 1 of UI element 1 of aRow
            end if
        end repeat
	    repeat
            delay 0.3
            if sheet 1 of window 1 of application process "System Preferences" exists then exit repeat
        end repeat
	    click button 1 of sheet 1 of window 1 of application process "System Preferences"
        activate application "System Preferences"
        end tell"""

    popup_fmm_guide_options = {
                            'icon-path': '{}/FindMy.icns'.format(ICONS_DIR),
                            'window-position': 'left-top',
                            'window-title': 0,
                            'window-title-text': 'FindMyMac deactivation',
                            'description-text': 'Please, turn off Find My Mac here.\n\nThanks!',
                            'ok-button-text': 'Oh, not now :(',
                            'action-button': 0
                            }

    popup_fmm_guide_options_detailed = {
                            'icon-path': '{}/FindMy.icns'.format(ICONS_DIR),
                            'window-position': 'left-top',
                            'window-title': 0,
                            'window-title-text': 'FindMyMac deactivation',
                            'description-text': 'Please, find Find My Mac among other apps using iCloud and turn it off.\n\nThanks!',
                            'ok-button-text': 'Oh, not now :(',
                            'action-button': 0
                            }

    def version_to_compare(version):
        return tuple(map(int, (version.split("."))))

    def run_osascript(osascript):
        args = ['2', '2']
        p = subprocess.Popen(['osascript', '-'] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(bytes(osascript,'UTF-8'))
        return p.returncode

    def open_fmm_settings(current_os_version):
        if version_to_compare(current_os_version) >= version_to_compare("15.0"):
            result = run_osascript(osascript_ge_15_0)
        elif version_to_compare(current_os_version) >= version_to_compare("14.0"):
            result = run_osascript(osascript_ge_14_0)
        elif version_to_compare(current_os_version) >= version_to_compare("13.3"):
            result = run_osascript(osascript_ge_13_3)
        elif version_to_compare(current_os_version) >= version_to_compare("13.0"):
            result = run_osascript(osascript_ge_13_0)
        elif version_to_compare(current_os_version) >= version_to_compare("11.0"):
            result = run_osascript(osascript_ge_11_0)
        return result

    run_command('killall "System Settings" "System Preferences" "Yandex.Popup"', shell = True)

    while True:
        code, out, err = run_command('open "x-apple.systempreferences:com.apple.preferences.AppleIDPrefPane?iCloud"', shell = True)
        if code == 0:
            break

    time.sleep(3)

    if mdm_profile_installed:
        osascript_exit_status = open_fmm_settings(os_version)
    else:
        osascript_exit_status = 1

    log.info('Osascript exit status is {}'.format(osascript_exit_status))
    if osascript_exit_status == 0:
        log.info('Osascript execution OK')
        guide_popup_process = yandex_popup(popup_fmm_guide_options,True)
    else:
        log.info('Osascript execution FAILED')
        guide_popup_process = yandex_popup(popup_fmm_guide_options_detailed,True)

    while True:
        if not fmm_enabled():
            code, out, err = run_command('killall "Yandex.Popup"', shell=True)
            log.info('fmm deactivated successfully')
            code, out, err = run_command('killall "System Settings" "System Preferences"', shell=True)
            return True
        if guide_popup_process.poll() is not None:
            log.info('fmm popup closed, fmm still active')
            code, out, err = run_command('killall "System Settings" "System Preferences"', shell=True)
            return False

def main():

    log.info('start')


    # determining checks bundle

    RUN_STEPS = DEFAULT_STEPS + TRIGGERED_STEPS
    log.debug('run steps: {}'.format( RUN_STEPS) )


    # determining active user

    console_user = get_console_user()

    if console_user is False:
        finish(failed_steps='\n - Unable to determine current account\n', header_text='Error')
        sys.exit(1)


    log.info('console user determined as "{}"'.format(console_user))


    NEEDED_STEPS = []

    # calculating needed steps

    if 'remove_mdm_profile' in RUN_STEPS and mdm_enrolled():
        NEEDED_STEPS.append('remove_mdm_profile')

    if 'mdm_profile' in RUN_STEPS and (not mdm_enrolled() or 'remove_mdm_profile' in RUN_STEPS ):
        NEEDED_STEPS.append('mdm_profile')

    if 'fv2_enabled' in RUN_STEPS and not fv2_enabled():
        NEEDED_STEPS.append('fv2_enabled')

    if 'fv2_reissue' in RUN_STEPS and fv2_enabled():
        NEEDED_STEPS.append('fv2_reissue')

    if 'bootstrap' in RUN_STEPS and not bootstrap_escrowed() and bootstrap_allowed():
        NEEDED_STEPS.append('bootstrap')

    if 'find_my_mac' in RUN_STEPS and fmm_enabled():
        NEEDED_STEPS.append('find_my_mac')


    # greeting user

    greetings(needed_steps = NEEDED_STEPS)


    # iterating over checks


    FAILED_STEPS = []
    SUCCESS_STEPS = []


    # mdm profile removal

    if 'remove_mdm_profile' in RUN_STEPS and mdm_enrolled():
        if remove_mdm_profile():
            log.info('removed mdm profile')
        else:
            log.error('failed to remove mdm profile')


    # mdm profile

    if 'mdm_profile' in RUN_STEPS and not mdm_enrolled():
        log.info('mdm profile not installed')

        code, stdout, stderr = yandex_popup({
                # 'icon-name' : 'NSAdvanced',
                'icon-path'   : '{}/prefs_icon.png'.format(ICONS_DIR),
                'header-text' : 'MDM Profile is not installed',
                'description-text' : PRE_ENROLLMENT_INSTRUCTIONS,
                'ok-button-text' : 'Install MDM'
            })

        if code != 0:
            log.info('User aborted, exiting')
            sys.exit(0)

        enroll_mdm_profile(console_user)

        SUCCESS_STEPS.append('mdm_profile')

    # Find My Mac

    if 'find_my_mac' in RUN_STEPS and fmm_enabled():
        log.info('find my mac deactivation needed')
        fmm_deactivation_res = fmm_disable(mdm_enrolled())

        if not fmm_deactivation_res:
            FAILED_STEPS.append('find_my_mac')
        else:
            SUCCESS_STEPS.append('find_my_mac')

    # part with user password

    if not password_needed(RUN_STEPS, console_user):

        log.info('No user password needed operations, stopping')

        finish(success_steps = SUCCESS_STEPS, failed_steps = FAILED_STEPS)

        return


    user_password = get_user_auth(console_user)


    # fv2 enabled

    if 'fv2_enabled' in RUN_STEPS and not fv2_enabled():
        if user_password == None:
            FAILED_STEPS.append('fv2_enabled')
        else:
            log.info('fv2 need to be enabled')
            fv2_enable_res = enable_fv2(console_user, user_password)

            if not fv2_enable_res:
                FAILED_STEPS.append('fv2_enabled')
            else:
                SUCCESS_STEPS.append('fv2_enabled')


    # fv2 reescrow check

    if 'fv2_reissue' in RUN_STEPS and fv2_enabled():
        if user_password == None:
            FAILED_STEPS.append('fv2_reissue')
        else:
            log.info('fv2 key reissue needed')
            fv2_reissue_res = fv2_reissue(console_user, user_password)

            if not fv2_reissue_res:
                FAILED_STEPS.append('fv2_reissue')
            else:
                SUCCESS_STEPS.append('fv2_reissue')


    # bootstrap token

    if 'bootstrap' in RUN_STEPS and not bootstrap_escrowed() and bootstrap_allowed():
        if user_password == None:
            FAILED_STEPS.append('bootstrap')
        else:
            log.info('bootstrap token escrow needed')
            bootstrap_escrow_res = escrow_bootstrap(console_user, user_password)

            if not bootstrap_escrow_res:
                FAILED_STEPS.append('bootstrap')
            else:
                SUCCESS_STEPS.append('bootstrap')

    # finish

    finish(success_steps = SUCCESS_STEPS, failed_steps = FAILED_STEPS)

if __name__ == '__main__':

    main()

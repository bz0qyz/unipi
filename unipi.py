#!/usr/bin/env python3
"""
unipi.py

Created by Russell Cook<bz0qyz@protonmail.com> on 2019-02-20.
License: The Unlicense <https://unlicense.org>
https://github.com/bz0qyz

Modules:
  pathlib
  logging
  jinja2
  systemd
  daemon

Changelog:

"""
###
## Import Modules
###
import os
import sys
import time
from time import sleep
import tempfile
import signal
import json
import argparse
import configparser


## Daemon modules
import subprocess
from subprocess import Popen, PIPE

## logging modules
import logging
from systemd import journal

## http Modules
import requests
import urllib3
urllib3.disable_warnings()

from jinja2 import Template
from pprint import pprint
from pathlib import Path
import RPi.GPIO as GPIO

## Encryption modules
import base64
import uuid
from cryptography.fernet import Fernet

###
## Global Static Variables
###

## Main loop interval in seconds
main_loop_interval = 5
## Name of this application
app_name = 'unipi'
## Version of this application
app_version = '1.1.0'
## Description of this application
app_description = 'Daemon for controlling a shutdown switch and an LED for a unifi controller running on a Raspberry Pi.'

## Dictionary of all default Variables
defaults = {}

## Dynamic path to this application directory. Primarily used for testing, not for daemon use.
defaults['app_path'] = os.path.dirname(os.path.realpath(__file__))
defaults['config_path'] = defaults['app_path'] + os.sep + 'etc'

## A string to prepend to a password that is stored in an encrypted format
defaults['pw_enc_prefix'] = 'enc::'

## Application configuration file in json format
defaults['config_file'] = defaults['config_path'] + os.sep + 'config.json'
## Defaut application settings. Can be changed by arguments and the 'config_file'
defaults['gpio_pin_led'] = 20
defaults['gpio_pin_shutdown'] = 16
defaults['shutdown_press_timeout'] = 5
defaults['status_query_interval'] = 30

## Unifi credentials file in ini format
defaults['unifi_access_file'] = defaults['config_path'] + os.sep + "unifi_access.ini"
## Defaut Unifi connection settings. Can be changed by arguments and the 'unifi_access_file'
defaults['unifi_host'] = 'localhost'
defaults['unifi_port'] = 8443
defaults['unifi_proto'] = 'https'
defaults['unifi_uri_settings'] = '/api/s/default/rest/setting'
defaults['unifi_uri_auth'] = '/api/login'

## Default pid file
defaults['pid_file'] = tempfile.gettempdir() + os.sep + app_name + '.pid'

## default logging options
defaults['syslog_id'] = 'com.64byte.' + app_name
defaults['syslog_facility'] = 'local0'

## default LED status
defaults['led_enabled'] = False

## Installation Variables
installvars = {}
installvars['example_unifi_access_file'] = defaults['unifi_access_file'] + '.example'
installvars['example_config_file'] = defaults['config_file'] + '.example'
installvars['install_prefix'] = '/usr/local'
installvars['pid_dir'] = '/var/run'
installvars['runas_user'] = 'root'
installvars['runas_group'] = 'root'
installvars['systemd_unit_path'] = '/etc/systemd/system'
installvars['systemd_unit_file'] = installvars['systemd_unit_path'] + '/' + app_name + '.service'
installvars['unit_template'] = Template(
'''[Unit]
Description={{app_description}}
After=unifi.service

[Service]
User={{user}}
Group={{group}}
KillMode=process
PIDFile={{pid_file}}
Type=forking
NotifyAccess=all
ExecStart=/usr/bin/python3 {{daemon}} --daemon --pid-file {{pid_file}} --config-file={{config_file}} --unifi-access-file={{access_file}}
StandardOutput=syslog+console
SyslogIdentifier={{app_name}}
SyslogFacility={{syslog_facility}}

[Install]
WantedBy=multi-user.target'''
)


###
## Initialize the GPIO
###
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

###
## HTTP Requests
###
http_session = requests.Session()

###
## Process command-line arguments
###
parser = argparse.ArgumentParser(description='Description of ' + app_name)
parser.add_argument('-c','--config-file',  metavar=defaults['config_file'], default=defaults['config_file'], help='Configuration file (json format).')
parser.add_argument('-d','--daemon', action="store_true", default=False, help='Run as a background daemon.')
parser.add_argument('-p','--pid-file', default=defaults['pid_file'], metavar=defaults['pid_file'], help='Daemon PID file')
parser.add_argument('-V','--version', action="store_true", default=False, help='Show version and exit.')
parser.add_argument('-v','--verbose', action="store_true", default=False, help='Show verbose output.')
parser.add_argument('--install', action="store_true", default=False, help='Install the program and systemd service / unit file')
parser.add_argument('--uninstall', action="store_true", default=False, help='Uninstall the systemd service / unit file')
parser.add_argument('--install-prefix', metavar=installvars['install_prefix'], default=installvars['install_prefix'], help='Installation Prefix path')
parser.add_argument('-u','--unifi-access-file', default=defaults['unifi_access_file'], metavar=defaults['unifi_access_file'], help='Unifi access file (ini format)')
parser.add_argument('-i','--unifi-host', metavar=defaults['unifi_host'], default=defaults['unifi_host'], help='Unifi controller hostname or IP Address')
parser.add_argument('-P','--unifi-port', metavar=defaults['unifi_port'], default=defaults['unifi_port'], type=int, help='Unifi controller port')
parser.add_argument('-o','--unifi-proto', metavar=defaults['unifi_proto'], default=defaults['unifi_proto'], help='Unifi controller protocol')
args = parser.parse_args()

###
## Global variable overrides from args
###
verbose = args.verbose
installvars['install_prefix'] = args.install_prefix
config = {}


###
############ INTERNAL FUNCTIONS ##################
###
def show_version():
    print(app_name + " Version: " + app_version)
    print(app_description)
    sys.exit(0)


def __signal_handler(signal, frame):
    objlog.info('Shutting down ' + app_name)
    pid_file_ops(args.pid_file)
    sys.exit(0)


def fatal(msg):
    ''' Python 3 '''
    print("\nFATAL: " + msg, file=sys.stderr)

    sys.exit(1)


def __system_cmd(cmd=''):
    proc = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    out, err = proc.communicate()
    if proc.returncode > 0:
        print("Warning! command exited with errors: {}".format(str(err.rstrip().decode("utf-8")) ))
        return False
    else:
        return True
def __is_root(die=False):
	## Verify that we are running with root privileges.
	if os.geteuid() != 0:
		if die:
			fatal("You must run this script with root privilegesto perform this action.")
		else:
			return False

###
## Service Uninstaller Function
###
def uninstall_service(installvars):
	__is_root(True)
	__system_cmd('systemctl stop ' + app_name + '.service')
	if __system_cmd('systemctl disable ' + app_name + '.service'):
		os.remove(systemd_unit_file)
		__system_cmd('systemctl daemon-reload')
		print("Successfully removed the systemd unit file and reloaded systemd")
		exit(0)
	else:
		exit(1)

###
## Service Installer Function
###
def install_service(installvars):
    __is_root(True)

    ## Create some re-usable variables for the installed files
    config_file = args.config_file.split(os.sep)[-1]
    unifi_access_file = args.unifi_access_file.split(os.sep)[-1]
    pid_file = installvars['pid_dir'] + args.pid_file.split(os.sep)[-1]

    install = {}
    install['config_dir']    = args.install_prefix + os.sep + 'etc' + os.sep + app_name
    install['config_file']   = install['config_dir'] + os.sep + config_file
    install['access_file']   = install['config_dir'] + os.sep + unifi_access_file
    install['bin_dir']       = args.install_prefix + os.sep + 'bin'
    install['daemon']        = install['bin_dir']  + os.sep + __file__.split(os.sep)[-1]

    ## Copyt Files to permanent installation locations
    print("Creating configuration directory: {}".format(install['config_dir']))
    __system_cmd('[ ! -d {} ] && mkdir -p {}'.format(install['config_dir'],install['config_dir']))

    print("Installing example configuration files...")
    print("File: {}".format(install['config_dir'] + os.sep + config_file ))
    __system_cmd('install -m 0600 -o root -g root {} {}'.format(installvars['example_config_file'], install['config_dir'] + os.sep + config_file))

    print("File: {}".format(install['config_dir'] + os.sep + unifi_access_file ))
    __system_cmd('install -m 0600 -o root -g root {} {}'.format(installvars['example_unifi_access_file'], install['config_dir'] + os.sep + unifi_access_file))

    print("Installing application...")
    __system_cmd('[ ! -d {} ] && mkdir -p {}'.format(install['bin_dir'],install['bin_dir']))
    __system_cmd('install -m 0755 -o root -g root {} {}'.format(__file__,install['daemon']))

    ## Write systemd Unit File
    unit_contents = installvars['unit_template'].render(
    app_description = app_description,
    app_name = app_name,
    syslog_facility = defaults['syslog_facility'],
    user = installvars['runas_user'],
    group = installvars['runas_group'],
    pid_file = pid_file,
    config_file = install['config_file'],
    access_file = install['access_file'],
    daemon = install['daemon']
    )
    fh = open(installvars['systemd_unit_file'], 'w')
    fh.write(unit_contents)
    fh.close()

    if __system_cmd('systemctl daemon-reload'):
        __system_cmd('systemctl enable ' + app_name + '.service')
        #__system_cmd('systemctl start ' + app_name + '.service')
        print("Successfully installed the systemd unit file and reloaded systemd")
        print("Edit the configuration files in '{}' before starting the service.".format(install['config_dir']))
        print("Logging to journal. Use command: 'journalctl -ef --unit={}' to view service logs".format(app_name))

    exit(0)

###
## PID File Operations
###
def pid_file_ops(pid_file,pid=None):
	if pid is not None:
		''' Write pid file'''
		try:
			fh = open(pid_file,'w')
			fh.write(str(pid))
			fh.close()
			return True
		except:
			return False
	else:
		''' Delete pid file'''
		try:
			os.remove(pid_file)
			return True
		except:
			return False


###
## Load Application Config file
###
def load_config(config_file):
	global verbose
	if os.path.isfile(config_file):
		if verbose:
			print("DEBUG: Configuration File = " + config_file)
		try:
			with open(config_file) as json_file:
				config = json.load(json_file)
		except ValueError as e:
			fatal("Error decoding json configuration file: " + config_file + "\nDetails: " + str(e) )
	else:
		fatal("Configuration file not found (" + config_file + ")")
	return config

###
## Load Unifi Access file
###
def load_access(unifi_access_file):
    global verbose
    unifi_config = configparser.ConfigParser()
    if os.path.isfile(unifi_access_file):
        if verbose:
            print("DEBUG: Unifi Access File = " + unifi_access_file)
        try:
            unifi_config.read_file(open(unifi_access_file))

            ## Encrypt the password if it's not encrypted
            secret = unifi_config.get(args.unifi_host,'password')
            if not secret.startswith(defaults['pw_enc_prefix']):
                msg = "INFO: detected unencrypted Unifi password. Encrypting password."
                if verbose:
                    print(msg)
                objlog.info(msg)
                try:
                    ## Encrypt the password
                    enc_password = defaults['pw_enc_prefix'] + __encrypt_pw(secret)
                    ## Save the encrypted string to the unifi_access_file
                    unifi_config.set(args.unifi_host,'password',enc_password)
                    unifi_config.write(open(unifi_access_file,'w'))
                except:
                    fatal("Error saving Unifi Access ini file: {}".format(unifi_access_file) )
        except:
            fatal("Error loading Unifi Access ini file: {}".format(unifi_access_file) )
    else:
        fatal("Unifi Access file not found (" + config_file + ")")
    return unifi_config

###
## Password Encryption
###
def __get_crypto_key():
    ## Generate a crypto key from this computer's uuid and pad it to 32 bytes
    ## This is more of an obfuscated way to store the password so it's not in plain text
    return  base64.urlsafe_b64encode(uuid.UUID(int=uuid.getnode()).bytes.ljust(32,b"\x0f"))


def __encrypt_pw(passin=''):
    key = __get_crypto_key()
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(passin.encode())
    return cipher_text.decode()

def __decrypt_pw(cipherin=''):

    key = __get_crypto_key()
    cipher_suite = Fernet(key)
    try:
        plain_text = cipher_suite.decrypt(cipherin.encode())
        return plain_text.decode()
    except:
        if verbose:
            print("ERROR: Unifi controller password decryption failed")
        objlog.error("ERROR: Unifi controller password decryption failed")
        return False

###
############ CORE FUNCTIONALITY FUNCTIONS ##################
###

###
## GPIO Cleanup
###
def cleanup(gpio_pin_led):
    ## Turn off the LED
    led_toggle(gpio_pin_led,False)
    GPIO.cleanup()

###
## Unifi Controller Authentication
###
def __unifi_login(unifi):
    global http_session

    ## Decrypt the password if it's encrypted
    if unifi['password'].startswith(defaults['pw_enc_prefix']):
        unsecure_pw =  __decrypt_pw(unifi['password'].lstrip(defaults['pw_enc_prefix']))
    else:
        ## In theory, this should never happen
        unsecure_pw = unifi['password']


    auth_dic={"username": unifi['username'],"password": unsecure_pw, "remember": "true", "strict": "true"}
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    url = "{}://{}:{}{}".format(unifi['proto'],unifi['hostname'], unifi['port'], unifi['unifi_uri_auth'])

    req = http_session.post(url,headers=headers,data=json.dumps(auth_dic),verify=False,timeout=5.0)

    ## Clear the unsecure_pw from memory
    unsecure_pw = None

    if req.status_code != requests.codes.ok:
        unifi['do_poll'] = False
        if verbose:
            print("Authentication Failed")
        objlog.error("ERROR: Unifi authentication failed. We will no longer check the site settings.")
        return False
    else:
        if verbose:
            print("DEBUG: Unifi Authentication successful.")
        objlog.info("INFO: Unifi Authentication successful.")
        return True

###
## Unifi Controller Query for Site Settings
###
def __unifi_get_settings(unifi):
    global http_session

    if unifi['do_poll']:
        if verbose:
            print("checking Unifi site settings")
        ## Query Site settings
        url = "{}://{}:{}{}".format(unifi['proto'],unifi['hostname'], unifi['port'], unifi['unifi_uri_settings'])
        try:
            req = http_session.get(url,verify=False,timeout=5.0)

            if req.status_code == requests.codes.unauthorized:
                __unifi_login(unifi)
                __unifi_get_settings(unifi)
            else:
                unifi['last_poll'] = time.time()
                unifi_settings = json.loads(req.content.decode("utf-8"))
                for section in unifi_settings['data']:
                    if section['key'] == "mgmt":
                        if verbose:
                            print("Unifi site LED enabled: {}".format(section['led_enabled']))
                        unifi['led_enabled'] = section['led_enabled']
                return unifi['led_enabled']
        except:
            errmsg = "ERROR: Unifi connection failed. Sleeping for 30 seconds before a retry."
            if verbose:
                print(errmsg)
            objlog.error(errmsg)
            errmsg = None
            time.sleep(30)
            __unifi_get_settings(unifi)


    else:
        return False

###
## Toggle the Status LED
###
def led_toggle(gpio_pin_led,status=True):
    if status and GPIO.input(gpio_pin_led) == GPIO.LOW:
        ## Turn On the LED
        objlog.info("INFO: Status LED Turned on.")
        GPIO.output(gpio_pin_led,GPIO.HIGH)
    if not status and GPIO.input(gpio_pin_led) == GPIO.HIGH:
        ## Turn Off the LED
        objlog.info("INFO: Status LED Turned off.")
        GPIO.output(gpio_pin_led,GPIO.LOW)

###
## Unifi Controller LED Settings main function
###
def led_setting(unifi):
    ## Only poll the unifi controller if the status query threshold is past
    poll_age =  time.time() - unifi['last_poll']
    #print("last_poll: {}".format(unifi['last_poll']))
    #print("current_clock: {}".format(time.time()))
    #print("Difference: {}".format(poll_age))

    if unifi['last_poll'] == 0 or poll_age >= config['global']['status_query_interval']:
        return __unifi_get_settings(unifi)
    else:
        return unifi['led_enabled']


###
## System Shutdown
###
def shutdown_system(gpio_pin_led):
    ## fast blink the LED to indicate shutown is imminent
    for i in range(1,6):
        led_toggle(gpio_pin_led,False)
        sleep(.3)
        led_toggle(gpio_pin_led,True)
        sleep(.3)

    if verbose:
        print("Shuting Down Pi")
    objlog.info("INFO: Button pressed for specified duration. Shutting Down System.")
    sleep(1)
    ## Execute the shutdown command
    __system_cmd("sudo nohup shutdown -h now")
    exit()


###
######################## MAIN FUNCTION ##############################
###
if __name__ == "__main__":
    signal.signal(signal.SIGINT, __signal_handler)
    if args.version:
        show_version()

    if verbose:
        print('DEBUG: Arguments: ')
        pprint(args)
        print('verbose is:', str(verbose))


    ###
    ## Setup the global logging object
    ###
    try:
        logger_name = config['global']['logging']['objname-prefix'] + '.' + app_name
    except:
        logger_name = defaults['syslog_id']
    objlog = logging.getLogger(logger_name)
    if verbose:
        objlog.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    else:
        objlog.setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)

    objlog.addHandler(journal.JournaldLogHandler())
    objlog.info('Starting up ' + app_name)


    ###
    ## Process install related arguments
    ###
    if args.install:
    	install_service(installvars)
    if args.uninstall:
    	uninstall_service(installvars)
    ## Clear up install variables since we don't need them
    installvars = None

    ###
    ## Load configuration Files
    ###

    ## Main application configuration
    config = load_config(args.config_file)

    ## Unifi Connection configuration
    unifi_config = load_access(args.unifi_access_file)
    unifi = {"hostname": args.unifi_host, "port": args.unifi_port, "proto": args.unifi_proto, "username": "", "password": "","led_enabled": False, "last_poll": 0, "do_poll": True}
    try:
        unifi['username'] = unifi_config.get(args.unifi_host,'username')
        unifi['password'] = unifi_config.get(args.unifi_host,'password')
    except:
        fatal("Unable to load Unifi access configuration for host name: {}".format(args.unifi_host))
    ## Override port from unifi_access_file
    try:
        unifi['port'] = unifi_config.get(args.unifi_host,'port')
    except:
        pass
    ## Override proto from unifi_access_file
    try:
        unifi['proto'] = unifi_config.get(args.unifi_host,'proto')
    except:
        pass
    ## Override Settings URI from unifi_access_file
    try:
        unifi['unifi_uri_settings'] = unifi_config.get(args.unifi_host,'unifi_uri_settings')
    except:
        unifi['unifi_uri_settings'] = defaults['unifi_uri_settings']
    ## Override Authentication URI from unifi_access_file
    try:
        unifi['unifi_uri_auth'] = unifi_config.get(args.unifi_host,'unifi_uri_auth')
    except:
        unifi['unifi_uri_auth'] = defaults['unifi_uri_auth']

    if verbose:
        print("DEBUG: connecting to unifi controller with the following settings")
        pprint(unifi)


    ###
    ## Startup in daemon mode
    ###
    if args.daemon:
        ''' Do the Double Fork '''
        # try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)

        # Decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        ''' Do second fork '''
        # try:
        pid = os.fork()
        if pid > 0:
            # Exit second parent
            pid_file_ops(args.pid_file,pid)
            sys.exit(0)


    ###
    ## Setup the application run variables
    ###
    if not 'gpio_pin_led' in config['global']:
        config['global']['gpio_pin_led'] = defaults['gpio_pin_led']

    if not 'gpio_pin_shutdown' in config['global']:
        config['global']['gpio_pin_shutdown'] = defaults['gpio_pin_shutdown']

    if not 'shutdown_press_timeout' in config['global']:
        config['global']['shutdown_press_timeout'] = defaults['shutdown_press_timeout']

    if not 'status_query_interval' in config['global']:
        config['global']['status_query_interval'] = defaults['status_query_interval']

    if verbose:
        print('DEBUG:')
        pprint(config)

    try:
        objlog.debug("Setting up GPIO LED")
        GPIO.setup(config['global']['gpio_pin_led'],GPIO.OUT)
        objlog.debug("Setting up GPIO Button")
        GPIO.setup(config['global']['gpio_pin_shutdown'],GPIO.IN,pull_up_down=GPIO.PUD_DOWN)

        ## Turn on the LED if unifi site setting is True
        objlog.debug("Setting Unifi LED to configured status")
        led_toggle(config['global']['gpio_pin_led'],led_setting(unifi))


        ''' Start the daemon loop '''
        press_count = 0
        while True:

            while GPIO.input(config['global']['gpio_pin_shutdown']) == GPIO.HIGH:
                led_toggle(config['global']['gpio_pin_led'],True)
                sleep(.5)
                led_toggle(config['global']['gpio_pin_led'],False)
                sleep(.5)
                press_count += 1
                #print("Button pressed {}".format(press_count))

                if press_count == config['global']['shutdown_press_timeout']:
                    shutdown_system(config['global']['gpio_pin_led'])
            else:
                if press_count > 0:
                    ## Set the LED status back to what it should be
                    led_toggle(config['global']['gpio_pin_led'],unifi['led_enabled'])
                    press_count = 0
                else:
                    led_toggle(config['global']['gpio_pin_led'],led_setting(unifi))

                sleep(main_loop_interval)


    finally:
        cleanup(config['global']['gpio_pin_led'])

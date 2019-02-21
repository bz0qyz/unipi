#!/usr/bin/env python3
"""
unipi.py

Created by Russell Cook<rcook@64byte.com> on 2019-02-20.
Copyright (c) 2018 64Byte.com, LLC All rights reserved.
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

###
## Global Static Variables
###
## Main loop timeout in seconds
main_loop_timeout = 5
## Name of this application
app_name = 'unipi'
## Version of this application
app_version = '1.0.1'
## Description of this application
app_description = 'Daemon for controlling an LED for a unifi controller running on a Raspberry Pi.'
## Dynamic path to this application directory
app_path = os.path.dirname(os.path.realpath(__file__))
config_path = app_path + os.sep + 'etc'
## Application configuration file in json format
config_file = config_path + os.sep + 'config.json'
## Unifi credentials file in ini format
unifi_access_file = config_path + os.sep + "unifi_access.ini"

pid_file = tempfile.gettempdir() + os.sep + app_name + '.pid'

## syslog facility - overide in the config file
default_syslog_facility='local0'
default_unifi_host = 'localhost'
default_unifi_port = 8443
default_shutdown_press_timeout = 10
default_led_enabled = False

## System path for systemd unit files
install_prefix = '/usr/local'
systemd_unit_path = '/etc/systemd/system'
systemd_unit_file = systemd_unit_path + '/' + app_name + '.service'
unit_template = Template(
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
parser.add_argument('-c','--config-file',  metavar=config_file, default=config_file, help='Configuration file (json format).')
parser.add_argument('-d','--daemon', action="store_true", default=False, help='Run as a background daemon.')
parser.add_argument('-V','--version', action="store_true", default=False, help='Show version and exit.')
parser.add_argument('-v','--verbose', action="store_true", default=False, help='Show verbose output.')
parser.add_argument('--install', action="store_true", default=False, help='Install the systemd service / unit file')
parser.add_argument('--uninstall', action="store_true", default=False, help='Uninstall the systemd service / unit file')
parser.add_argument('--start', action="store_true", default=False, help='Start the systemd service')
parser.add_argument('--stop', action="store_true", default=False, help='Stop the systemd service')
parser.add_argument('--restart', action="store_true", default=False, help='Restart the systemd')
parser.add_argument('-p','--pid-file', default=pid_file, metavar=pid_file, help='Daemon PID file')
parser.add_argument('-u','--unifi-access-file', default=unifi_access_file, metavar=unifi_access_file, help='Unifi access file (ini format)')
parser.add_argument('-i','--unifi-host', default=default_unifi_host, metavar=default_unifi_host, help='Unifi controller hostname or IP Address')
parser.add_argument('-P','--unifi-port', metavar=default_unifi_port, default=default_unifi_port, type=int,help='Unifi controller port')
#parser.add_argument('-b','--boolean', action="store_true", default=False, help='Example boolean argument')
#parser.add_argument('-s','--string',  metavar='string argument', help='Example string argument')
#parser.add_argument('-i','--integer', metavar='0', type=int, nargs='+',help='Example integer argument')
args = parser.parse_args()

###
## Global variable overrides
###
verbose = args.verbose
pid_file = args.pid_file
config = {}


###
############ INTERNAL FUNCTIONS ##################
###
def show_version():
    print(app_name + " Version: " + app_version)
    print(app_description)
    sys.exit(0)

def signal_handler(signal, frame):
    objlog.info('Shutting down ' + app_name)
    pid_file_ops(pid_file)
    sys.exit(0)


def fatal(msg):
    ''' Python 3 '''
    print("\nFATAL: " + msg, file=sys.stderr)

    sys.exit(1)

def system_cmd(cmd=''):
    proc = subprocess.Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    out, err = proc.communicate()
    if proc.returncode > 0:
        print("Warning! command exited with errors: {}".format(str(err.rstrip().decode("utf-8")) ))
        return False
    else:
        return True
def is_root(die=False):
	## Verify that we are running with root privileges.
	if os.geteuid() != 0:
		if die:
			fatal("You must run this script with root privilegesto perform this action.")
		else:
			return False

def cycle_service(action='start'):
	is_root(True)
	if action == 'start':
		system_cmd('systemctl start ' + app_name)
	elif action == 'stop':
		system_cmd('systemctl stop ' + app_name)
	elif action == 'restart':
		system_cmd('systemctl stop ' + app_name)
		time.sleep(2)
		system_cmd('systemctl start ' + app_name)
	else:
		exit(1)
	exit(0)

def uninstall_service():
	is_root(True)
	system_cmd('systemctl stop ' + app_name + '.service')
	if system_cmd('systemctl disable ' + app_name + '.service'):
		os.remove(systemd_unit_file)
		system_cmd('systemctl daemon-reload')
		print("Successfully removed the systemd unit file and reloaded systemd")
		exit(0)
	else:
		exit(1)

def install_service():
    is_root(True)

    ## Create some re-usable variables for the installed files
    config_file = args.config_file.split(os.sep)[-1]
    access_file = args.unifi_access_file.split(os.sep)[-1]
    pid_file = '/var/run/' + args.pid_file.split(os.sep)[-1]
    install = {}
    install['config_dir']    = install_prefix + os.sep + 'etc' + os.sep + app_name
    install['config_file']   = install['config_dir'] + os.sep + config_file
    install['access_file']   = install_prefix + os.sep + 'etc' + os.sep + app_name + os.sep + access_file
    install['daemon']        = install_prefix + os.sep + 'bin' + os.sep + __file__.split(os.sep)[-1]

    ## Copyt Files to permanent installation locations
    system_cmd('[ ! -d {} ] && mkdir {}'.format(install['config_dir'],install['config_dir']))
    system_cmd('install -m 0600 -o root -g root -t {} {} {}'.format(install['config_dir'],args.config_file,args.unifi_access_file))
    system_cmd('install -m 0755 -o root -g root {} {}'.format(__file__,install['daemon']))

    unit_contents = unit_template.render(
    app_path = app_path,
    app_description = app_description,
    app_name = app_name,
    syslog_facility = config['global']['logging']['syslog_facility'],
    user = config['global']['service']['runas']['user'],
    group = config['global']['service']['runas']['group'],
    pid_file = pid_file,
    config_file = install['config_file'],
    access_file = install['access_file'],
    daemon = install['daemon']
    )
    fh = open(systemd_unit_file, 'w')
    fh.write(unit_contents)
    fh.close()

    if system_cmd('systemctl daemon-reload'):
        system_cmd('systemctl enable ' + app_name + '.service')
        system_cmd('systemctl start ' + app_name + '.service')
        print("Successfully installed the systemd unit file and reloaded systemd")
        print("Logging to journal. Use command: 'journalctl -ef --unit=" + app_name + "' to view service logs")
    exit(0)

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
## Load Global Config file
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
    unifi = configparser.ConfigParser()
    if os.path.isfile(unifi_access_file):
        if verbose:
            print("DEBUG: Unifi Access File = " + unifi_access_file)
        try:
            unifi.read(unifi_access_file)
        except:
            fatal("Error loading Unifi Access ini file: {}".format(unifi_access_file) )
    else:
        fatal("Unifi Access file not found (" + config_file + ")")
    return unifi


###
## Application functions
###
def cleanup(gpio_pin_led):
    ## Turn off the LED
    led_toggle(gpio_pin_led,False)
    #print("Exiting Script")
    GPIO.cleanup()


def unifi_login(unifi):
    global http_session

    auth_dic={"username": unifi['username'],"password": unifi['password'], "remember": "true", "strict": "true"}
    #pprint(auth_dic)
    headers = {"Content-Type": "application/json;charset=UTF-8"}
    url = "https://{}:{}/api/login".format(unifi['hostname'], unifi['port'])

    req = http_session.post(url,headers=headers,data=json.dumps(auth_dic),verify=False,timeout=5.0)

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


def unifi_get_settings(unifi):
    global http_session

    if unifi['do_poll']:
        if verbose:
            print("checking Unifi site settings")
        ## Query Site settings
        url = "https://{}:{}/api/s/default/rest/setting".format(unifi['hostname'], unifi['port'])
        try:
            req = http_session.get(url,verify=False,timeout=5.0)

            if req.status_code == requests.codes.unauthorized:
                unifi_login(unifi)
                unifi_get_settings(unifi)
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
            unifi_get_settings(unifi)


    else:
        return False


def led_toggle(gpio_pin_led,status=True):
    if status and GPIO.input(gpio_pin_led) == GPIO.LOW:
        ## Turn On the LED
        #print("LED on")
        GPIO.output(gpio_pin_led,GPIO.HIGH)
    if not status and GPIO.input(gpio_pin_led) == GPIO.HIGH:
        ## Turn Off the LED
        #print("LED off")
        GPIO.output(gpio_pin_led,GPIO.LOW)

def led_setting(unifi):
    ## See if the status is stale
    poll_age =  time.time() - unifi['last_poll']
    #print("last_poll: {}".format(unifi['last_poll']))
    #print("current_clock: {}".format(time.time()))
    #print("Difference: {}".format(poll_age))

    if unifi['last_poll'] == 0 or poll_age >= config['global']['status_query_threshold']:
        return unifi_get_settings(unifi)
    else:
        return unifi['led_enabled']



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
    system_cmd("sudo nohup shutdown -h now")
    exit()


###
############ MAIN FUNCTION ##################
###
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    if args.version:
        show_version()

    if verbose:
        print('DEBUG: Arguments: ')
        pprint(args)
        print('verbose is:', str(verbose))

    config = load_config(args.config_file)
    unifi_config = load_access(args.unifi_access_file)
    unifi = {"hostname": args.unifi_host, "port": args.unifi_port, "username": "", "password": "","led_enabled": False, "last_poll": 0, "do_poll": True}
    try:
        unifi['username'] = unifi_config.get(args.unifi_host,'username')
        unifi['password'] = unifi_config.get(args.unifi_host,'password')
    except:
        fatal("Unable to load Unifi access configuration for host name: {}".format(args.unifi_host))
    try:
        unifi['port'] = unifi_config.get(args.unifi_host,'port')
    except:
        pass

    if verbose:
        print("DEBUG: connecting to unifi controller with the following settings")
        pprint(unifi)


    if verbose:
        print('DEBUG:')
        pprint(config)

    ###
    ## Process service related arguments
    ###
    ## If --install was called, just do that
    if args.install:
    	install_service()
    if args.uninstall:
    	uninstall_service()
    if args.start:
    	cycle_service('start')
    if args.stop:
    	cycle_service('stop')
    if args.restart:
    	cycle_service('restart')


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
            pid_file_ops(pid_file,pid)
            sys.exit(0)


    ###
    ## Setup the global logging object
    ###
    try:
        logger_name = config['global']['logging']['objname-prefix'] + '.' + app_name
    except:
        logger_name = app_name
    objlog = logging.getLogger(logger_name)
    if verbose:
        objlog.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    else:
        objlog.setLevel(logging.INFO)
        logging.getLogger("urllib3").setLevel(logging.INFO)

    objlog.addHandler(journal.JournaldLogHandler())
    objlog.info('Starting up ' + app_name)


    gpio_pin_led = config['global']['gpio_pin_led']
    gpio_pin_shutdown = config['global']['gpio_pin_shutdown']
    try:
        shutdown_press_timeout = config['global']['shutdown_press_timeout']
    except:
        shutdown_press_timeout = default_shutdown_press_timeout

    try:
        objlog.debug("Setting up GPIO LED")
        GPIO.setup(gpio_pin_led,GPIO.OUT)
        objlog.debug("Setting up GPIO Button")
        GPIO.setup(gpio_pin_shutdown,GPIO.IN,pull_up_down=GPIO.PUD_DOWN)

        ## Turn on the LED if unifi site setting is True
        objlog.debug("Setting Unifi LED to configured status")
        led_toggle(gpio_pin_led,led_setting(unifi))


        ''' Start the daemon loop '''
        press_count = 0
        while True:

            while GPIO.input(gpio_pin_shutdown) == GPIO.HIGH:
                led_toggle(gpio_pin_led,True)
                sleep(.5)
                led_toggle(gpio_pin_led,False)
                sleep(.5)
                press_count += 1
                #print("Button pressed {}".format(press_count))

                if press_count == shutdown_press_timeout:
                    shutdown_system(gpio_pin_led)
            else:
                if press_count > 0:
                    ## Set the LED status back to what it should be
                    led_toggle(gpio_pin_led,unifi['led_enabled'])
                    press_count = 0
                else:
                    led_toggle(gpio_pin_led,led_setting(unifi))

                sleep(1)
            #sleep(1)


    finally:
        cleanup(gpio_pin_led)

# UniPi
### A daemon for controlling a shutdown switch and an LED for a unifi controller running on a Raspberry Pi.

## Disclaimer
This code is distributed with a **use at your own risk** warning. The author is not responsible for any damages to systems or hardware.

## Details / Features
- Enables or Disables an LED based on the Unifi controller site settings.
- Watches a momentary switch for a long press (n seconds).
  - While pressing the switch, the LED will flash
  - When the button press reaches the time threshold, the LED will fast-blink to indicate that the system shutown is imminent. Then the operating system is issued a `shutdown -h now` command.
- Runs as a systemd daemon using journald for logging.

## Requirements
- Systemd
- Python Version 3.x
- Python Modules (extra):
  - RPi.GPIO
  - requests
  - systemd
  - pathlib
  - jinja2

 Requirements can be installed with the following commands:

 ```bash
sudo apt install -y python3 python3-pip libsystemd-dev
sudo pip install --upgrade -r requirements.txt
 ```

## Usage
### Installation
The main python script has an argument for installation `--install`, however it is immature and you will need to do some manual tasks to get everything working correctly.

The installer will copy / create files to locations based on the installation prefix. By default the prefix is `/usr/local`, however it can be specified by using the `--install-prefix` command argument.

The automated install will do the following:
- Copy the main script (itself) `unipi.py` to `[prefix]/bin` with execute permissions
- Copy the example configuration files to `[prefix]/etc/unipi`. They will be owned by root with a umask of `0600`
- Create a systemd unit file: `/etc/systemd/system/unipi.service`, and enable it.

### Configuration
You will need to edit the configuration files to match your installation and GPIO pins.
- `[prefix]/etc/unipi/config.json`
  - **gpio_pin_led:** BCM pin ID for the status LED.
  - **gpio_pin_shutdown:** BCM pin ID for the shutdown button.
  - **shutdown_press_timeout:** Number of seconds to press the button before shutting down the operating system.
  - **status_query_interval:** Number of seconds between polling the Unifi API for the LED status.
- `[prefix]/etc/unipi/unifi_access.ini`
  - Add the hostname, username and password to access your controller. I recommend that you create a read-only account on your controller for this. __On first run, the application will encrypt the password and write it back to this file__.

##### Password Encryption
There is a simple encryption method used to obfuscate the Unifi password stored in the `unifi_access.ini` file. The encryption key is generated from the operating system UUID and is therefore not very secure. This does mean that the access file cannot be copied between operating systems without re-generating the password encryption.


### Systemd Control
All service controls are executed through the `systemctl` command.
- `systemctl start|stop|restart|enable|disable unipi`

### Monitoring
The daemon log can be monitored (tailed) using journald with the following command
- `journalctl -ef --unit=unipi`

## Current Version Considerations
- Runs as root only
- Requires systemd / journald
- LED status polling only checks the `default` Site on the Unifi Controller. This could be manually changed by altering the `defaults['unifi_uri_settings']` variable.
- Button polling loop and LED status loop are running in the same thread/loop so it is not currently possible to decouple them without modifying the code.
- English language only.

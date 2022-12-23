Fake MQTT server
===================

# About

This is a fake MQTT server that will send some hardcoded answers to a client and then will exit.

Tuya-based iot devices wait until succcessfull MQTT connection before starting local RTSP. Which makes them useless for offline usage. However if you have unlocked root access, you can patch your `ppsapp`, start the fake mqtt server on the device and enjoy fully offline off-cloud RTSP.

# Requirements

* root access
* patched ppsapp with replaced CA certificate
* hex editor
* microSD card

For rooting and unlocking your device check the following repos and their wikis, it's a gold mine:

* https://github.com/guino/Merkury720
* https://github.com/guino/Merkury1080P
* https://github.com/guino/ppsapp-rtsp

To patch `ppsapp` and replace the cerificate you must use hex editor, find DER certificate inside the binary and replace it with yours.

# Compile

Download ARM toolchain. I sued this one:

* https://toolchains.bootlin.com/releases_armv5-eabi.html
* armv5-eabi--uclibc--stable-2018.02-2
* https://toolchains.bootlin.com/downloads/releases/toolchains/armv5-eabi/tarballs/armv5-eabi--uclibc--stable-2018.02-2.tar.bz2

Add compiler to your path:

`export PATH=$PATH:/path/to/toolchain/bin`

Verify that you can run gcc:

`arm-buildroot-linux-uclibcgnueabi-gcc`

Compile:

```
CC=arm-buildroot-linux-uclibcgnueabi-gcc LDFLAGS="-static" make no_test
```


The server will be located at `programs/ssl/ssl_server`. Copy it to the microSD card and name `fake_mqtt`.

# Run

Before running make sure that device's hosts file is redirecting domains to localhost:

```
echo "127.0.0.1    m2.tuyaeu.com" > /etc/hosts
echo "127.0.0.1    a2.tuyaeu.com" >> /etc/hosts
```

(you may need to update domains according to your location)

From the root shell on the device:
```
cd /mnt/mmc01
killall -w ppsapp
./fake_mqtt &
/opt/pps/app/appfiles/app/ppsapp &
```

The device should establish the connection to your fake MQTT and this will allow the device to continue and start local RTSP.

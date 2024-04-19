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

To patch `ppsapp` and replace the cerificate you must use hex editor, find DER certificate inside the binary and replace it with yours. See here: https://github.com/guino/ppsapp-rtsp/issues/47#issuecomment-1359460388

# Compile

Download ARM toolchain. I used this one:

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

# Example console output

```
...
[01-01 02:00:06:244 TUYA Debug][tuya_iot_wifi_api.c:350] wifi netstat changed to:5  <<--
wpa_supplicant service ... [start] ok
  . Seeding the random number generator... ok
  . Loading the server cert. and key... ok
  . Bind on https://localhost:8883/ ... ok
  . Setting up the SSL data.... ok
  . Waiting for a remote connection ...
[01-01 02:00:07:150 TUYA Debug][mqc_app.c:916] get_gw_nw_status:0
[01-01 02:00:07:156 TUYA Err][mqtt_client.c:1126] mqtt task is not permit to execute. short sleep..
[01-01 02:00:08:227 TUYA Debug][mqc_app.c:916] get_gw_nw_status:0
...
[01-01 02:00:11:467 TUYA Debug][mqtt_client.c:1139] select mqtt host:m2.tuyaeu.com
[01-01 02:00:11:479 TUYA Notice][mqtt_client.c:1152] mqtt get serve ip success
[01-01 02:00:11:516 TUYA Debug][mqtt_client.c:816] serverIP 2130706433 port:8883
 ok  . Performing the SSL/TLS handshake...
 [01-01 02:00:11:541 TUYA Debug][mqtt_client.c:828] mqtt over TLS is enabled. Host:m2.tuyaeu.com Port:8883
...
[0m[01-01 02:00:12:692 TUYA Debug][tuya_tls.c:966] sock(35) Suit:TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256 Cost:1(setup)1130(shake)0(verify)
 ok < Read from client:
 [01-01 02:00:12:711 TUYA Debug][app_agent.c:917] Setup TCP Server On Port:6668
[01-01 02:00:12:721 TUYA Debug][mqtt_client.c:1180] mqtt socket create success. begin to connect
[01-01 02:00:12:761 TUYA Debug][mqc_app.c:401] TLS Mode is NOT TLS_DISABLE:4 .set username = gwid
 80 bytes read
 Write to client:Writing 4 bytes for request #1
 4 bytes written
[01-01 02:00:12:855 TUYA Notice][mqtt_client.c:1194] mqtt socket connect success. begin to subscribe 
 76 bytes read
 Write to client:Writing 6 bytes for request #2
 6 bytes written
[01-01 02:00:12:922 TUYA Debug][mqtt_client.c:909] mqtt subscribe success
[01-01 02:00:12:940 TUYA Debug][mqc_app.c:794] mqtt connected success
...
```

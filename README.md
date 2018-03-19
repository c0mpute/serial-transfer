# Serial-Transfer

## Description
**serial-transfer** is useful for transferring files over a serial interface when the device has a very limited 
BusyBox and no serial file transfer protocols such as X-Modem.

The tool assumes a root shell is available on the serial interface. It uses very basic Linux commands, as well 
as pure BASH base64 encoding/decoding scripts for file transfers.

**WARNING:** Because most devices use serial interfaces for debugging purposes (such as UART), random debugging 
output can appear at any time. While this does not affect the write functionality, file reads will most likely 
fail.

## Setting up

Assuming you have python installed

```
# Clone this repo
git clone git@github.com:c0mpute/serial-transfer.git ~/git/serial-transfer

## Install dependencies
sudo pip install pyserial 
sudo pip install pyserial termcolor
```

## Usage

serial-transfer.py [-h] [-V] {write,read} ...

serial-transfer.py read [-h] [-b] [-r RATE] [-i INPUT] [-o OUTPUT] dev
positional arguments:
dev                   Path to serial device
optional arguments:
-h, --help            show this help message and exit
-b, --base64          Use base64 encoding (smaller overhead, might not work on all systems)
-r RATE, --rate RATE  Baud rate [Default: 115200]
-i INPUT, --input INPUT Input file/directory path (on target system)
-o OUTPUT, --output OUTPUT Output file/directory path (on local host)

serial-transfer.py write [-h] [-b] [-r RATE] [-i INPUT] [-o OUTPUT] [-c CHUNK_SIZE] [-p PERM] dev
positional arguments:
  dev                   Path to serial device
optional arguments:
-h, --help            show this help message and exit
-b, --base64          Use base64 encoding (smaller overhead, might not work on all systems)
-r RATE, --rate RATE  Baud rate [Default: 115200]
-i INPUT, --input INPUT Input file/directory path (on local host)
-o OUTPUT, --output OUTPUT Output file/directory path (on target system) [Default: /tmp]
-c CHUNK_SIZE, --chunk-size CHUNK_SIZE Transfer chunk size (in bytes) [Default: 768]
-p PERM, --perm PERM  Octal permissions [Default: 644]
  
**NOTE:** serial-transfer will preserve directory structure for reading/writing files. 
Example:
serial-transfer.py read -b -r 115200 -i /etc/shadow -o /tmp 
File saved to /tmp/etc/shadow

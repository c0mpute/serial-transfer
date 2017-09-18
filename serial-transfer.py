#!/usr/bin/env python

import serial
import sys
import getopt
import os
import io
import re
from time import sleep
from termcolor import colored
import textwrap
import time
import argparse
import base64
from os import walk
from argparse import RawTextHelpFormatter

REPEAT = 5
IO_TIME = .2
INPUT_BUFFER = 4096 * 1024

DEFAULT_CHUNK_SIZE = 768
DEFAULT_PERM = '644'
DEFAULT_BAUD_RATE = 115200

DEFAULT_RPATH = "/tmp"
DEFAULT_TMPPATH = "/tmp/chunk"
DEFAULT_LPATH = os.path.realpath(os.path.dirname(__file__)) + "/encoding-scripts"

DEFAULT_LPATH_B64D = "%s/b64d.sh" % DEFAULT_LPATH
DEFAULT_LPATH_B64 = "%s/b64.sh" % DEFAULT_LPATH
DEFAULT_LPATH_BASE64 = "%s/base64.sh" % DEFAULT_LPATH
DEFAULT_LPATH_HEXDUMP = "%s/bash-hexdump.sh" % DEFAULT_LPATH

DEFAULT_RPATH_B64D = "%s/b64d.sh" % DEFAULT_RPATH
DEFAULT_RPATH_B64 = "%s/b64.sh" % DEFAULT_RPATH
DEFAULT_RPATH_BASE64 = "%s/base64.sh" % DEFAULT_RPATH
DEFAULT_RPATH_HEXDUMP = "%s/bash-hexdump.sh" % DEFAULT_RPATH




def get_running_path():
    return os.path.realpath(os.path.dirname(__file__)) + '/'

def encode_hex(str):
    return "\\x" + "\\x".join([c.encode('hex') for c in str])

def decode_hex(str):
    return "".join([c.decode('hex') for c in str.split("\\x")])

def encode_b64(str):
    return base64.b64encode(str)

def decode_b64(str):
    return base64.b64decode(str)

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)

def write_ser(ser, str):
    ser.write(unicode(str))
    ser.flush()

def read_ser(ser, len=INPUT_BUFFER):
    s = ''
    while True:
        chunk = escape_ansi(ser.read(INPUT_BUFFER))
        s += chunk
        if not chunk: break
    return s[s.find('\n') + 1:s.rfind('\n')] #remove first and last lines from output

def exec_cmd(ser, cmd):
    write_ser(ser, cmd + '\n')
    return read_ser(ser)

def list_rdir(ser, path):
    cmd = 'd=; ls -R1 %s | while read l; do case $l in *:) d=${l%:};; "") d=;; /*) echo "$l";; *) ! [ -d "$d/$l" ] && echo "$d/$l";; esac; done' % path
    return exec_cmd(ser, cmd).splitlines()

def get_bin_size(ser, path):
    size = -1
    write_ser(ser, "ls -l %s\n" % (path))
    ret = read_ser(ser)
    for line in ret.splitlines():
        if path in line and "ls -l" not in line:
            size = int(re.findall(r'\S+', line)[4].strip())
            break
    return size

def rpath_exists(ser, path):
    cmd = "ls %s >/dev/null 2>&1; echo $?" % path
    ret = exec_cmd(ser, cmd)
    return "0" in ret

def rpath_isdir(ser, path):
    cmd = "[ -d %s ] && echo is_dir" % path
    ret = exec_cmd(ser, scmd)
    return "is_dir" in ret

def rpath_isglob(path):
    return "*" in path

def write_chunk(ser, chunk_data, rpath, base64=True):
    repeat_try = 0
    write_size = 0
    chunk_size = len(chunk_data)/4
    cmd = "printf '%s' > %s" % (chunk_data, DEFAULT_TMPPATH)
    while write_size != chunk_size and repeat_try < REPEAT:
        write_ser(ser, cmd)
        sleep(IO_TIME)
        read_ser(ser)
        write_size = get_bin_size(ser, DEFAULT_TMPPATH)
        repeat_try +=1
        if repeat_try >= REPEAT:
            print("[+] Failed writing chunk... Exiting")
            exec_cmd(ser, "rm -f %s" % rpath)
            return -1
    if base64:
        cmd = "cat %s | %s >> %s" % (DEFAULT_TMPPATH, DEFAULT_RPATH_B64D, rpath)
    else:
        cmd = "cat %s >> %s" % (DEFAULT_TMPPATH, rpath)
    exec_cmd(ser, cmd)
    exec_cmd(ser, "rm -f %s" % DEFAULT_TMPPATH)
    return write_size


def write_enc(ser, hex_arr, rpath, chunk_size=DEFAULT_CHUNK_SIZE, base64=True):
    print("[+] [CHUNK SIZE] : %d" % (chunk_size))
    total_bytes = (len(hex_arr) - 1) * chunk_size
    total_bytes += len(hex_arr[-1])
    write_chunk(ser, hex_arr[0], rpath, base64)
    bytes_written = chunk_size
    progress = int(float(float(bytes_written) / float(total_bytes)) * 100)
    sys.stdout.write("\r[+] [Progress: %d B/%d B (%d %%)]" % (bytes_written, total_bytes, progress))
    sys.stdout.flush()
    for p in hex_arr[1:]:
        write_chunk(ser, p, rpath, base64)
        bytes_written += len(p)
        progress = int(float(float(bytes_written) / float(total_bytes)) * 100)
        sys.stdout.write("\r[[+] Progress: %d B/%d B (%d %%)]" % (bytes_written, total_bytes, progress))
        sys.stdout.flush()
    sys.stdout.write('\n')
    return get_bin_size(ser, rpath)

def write_file(ser, lpath, rpath, chunk_size=DEFAULT_CHUNK_SIZE, perm='644', base64=True):
    file_size = os.path.getsize(lpath)
    write_size = 0
    enc_str = ''
    rdir = os.path.dirname(rpath)
    exec_cmd(ser, "mkdir -p %s" % rdir)

    with open(lpath, 'rb') as file:
        if base64:
            enc_str = encode_b64(file.read())
        else:
            enc_str = encode_hex(file.read())
        file.close()
    arr = textwrap.wrap(enc_str, chunk_size)
    print("[+] Writing file %s to %s..." % (lpath, rpath))
    while True:
        write_size = write_enc(ser, arr, rpath, chunk_size, base64)
        if write_size == file_size: break
        if write_size == -1:
            print("[+] Could not determine file size on target device... Continuing without size validation")
            break
        print("[+] File size not matching...Written file size: %d...Actual file size: %d" % (write_size, file_size))
        print("[+] Retrying file write...")
        cmd = "rm -f %s" % rpath
        exec_cmd(ser, cmd)
    print("[+] Setting file permissions...")
    cmd = "chmod %s %s" % (perm, rpath)
    ret = exec_cmd(ser, cmd)
    if "Permission denied" in ret:
        print("[+] Setting permissions failed. Permission denied")
        return 0
    elif cmd in ret:
        print("[+] File permissions set")
        return 1
    else:
        print("[+] Setting permissions failed with unknown error")
        return 0

def write_files(ser, lpath, rpath, chunk_size=DEFAULT_CHUNK_SIZE, perm='644', base64=True, nodirstruct=False):
    if os.path.exists(lpath) and base64:
        print("[+] Transferring base64 decode script...")
        if write_file(ser, DEFAULT_LPATH_B64D, DEFAULT_RPATH_B64D, chunk_size, '777', False):
            print("[+] Base64 decode script transferred successfully")
        else:
            print("[+] Failed base64 decode script transfer...Attempting hexdump transfer")
            cmd = "rm -f %s" % DEFAULT_RPATH_B64D
            exec_cmd(ser, cmd)
            base64 = False
    if os.path.isdir(lpath):
        for(subdir, dirs, files) in walk(lpath):
            for f in files:
                local_path = subdir + os.sep + f
                if nodirstruct:
                    remote_path = rpath
                else:
                    remote_path = rpath + os.sep + local_path
                write_file(ser, local_path, remote_path, chunk_size, perm, base64)
    elif os.path.isfile:
        write_file(ser, lpath, rpath, chunk_size, perm, base64)


def read_file(ser, rpath, lpath="./", base64=True):
    if not rpath_exists(ser, rpath):
        print("[+] File %s does not exist on target system") % rpath
        return 1
    lpath += rpath
    ldir = os.path.dirname(lpath)
    os.path.makedirs(ldir)
    if base64:
        cmd = "cat %s | %s" % (rpath, DEFAULT_RPATH_B64)
        ret = decode_b64(exec_cmd(ser, cmd))
    else:
        cmd = "%s %s" % (DEFAULT_RPATH_HEXDUMP, rpath)
        ret = parse_hexdump(exec_cmd(ser, cmd))
    f = open(lpath, 'w')
    f.write(ret)
    f.close()
    print("[+] File saved to %s" % lpath)
    return 0

def read_files(ser, rpath, lpath="./", base64=True):
    if not rpath_exists(ser, rpath):
        print("[+] Remote path %s does not exist on target system") % rpath
        return 1
    if base64:
        if write_file(ser, DEFAULT_LPATH_B64, DEFAULT_RPATH_B64, chunk_size, '777', False):
            print("[+] Base64 decode script transferred successfully")
        else:
            print("[+] Failed base64 decode script transfer")
            cmd = "rm -f %s" % DEFAULT_RPATH_B64
            exec_cmd(ser, cmd)
            if write_file(ser, DEFAULT_LPATH_HEXDUMP, DEFAULT_RPATH_HEXDUMP, chunk_size, '777', False):
                print("[+] Hexdump script transferred successfully")
                base64 = False
            else:
                print("[+] Failed hexdump script transfer")
                cmd = "rm -f %s" % DEFAULT_RPATH_HEXDUMP
                exec_cmd(ser, cmd)
                return 1
    else:
        if write_file(ser, DEFAULT_LPATH_HEXDUMP, DEFAULT_RPATH_HEXDUMP, chunk_size, '777', False):
            print("[+] Hexdump script transferred successfully")
        else:
            print("[+] Failed hexdump script transfer")
            cmd = "rm -f %s" % DEFAULT_RPATH_HEXDUMP
            exec_cmd(ser, cmd)
            return 1

    if rpath_isdir(ser, rpath) or rpath_isglob(rpath):
        files = list_rdir(ser, rpath)
        for f in files:
            read_file(ser, f, lpath, base64)
        return 0
    else:
        return read_file(ser, rpath, lpath, base64)

def parse_hexdump(dump):
    ret = ''
    for line in dump.splitlines():
        t = line.split('  ')
        for x in t:
            if '|' not in x:
                y = x.split(' ')
                if len(y) > 1:
                    for z in y:
                        ret += z.decode('hex')
    return ret

def parse_write(args):
    if not args.input:
        print("Input path not specified")
        return 1
    ser = serial.Serial(args.dev, int(args.rate), timeout=1, xonxoff=True, rtscts=True, dsrdtr=True)
    ser.flushInput()
    ser.flushOutput()
    ser.flush()
    ser.nonblocking()
    sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser, buffer_size=INPUT_BUFFER), encoding='latin1')
    return write_files(sio, args.input, args.output, args.chunk-size, args.perm, args.base64, args.nodirstruct)

def parse_read(args):
    if not args.input:
        print("Input path not specified")
        return 1
    ser = serial.Serial(args.dev, int(args.rate), timeout=1, xonxoff=True, rtscts=True, dsrdtr=True)
    ser.flushInput()
    ser.flushOutput()
    ser.flush()
    ser.nonblocking()
    sio = io.TextIOWrapper(io.BufferedRWPair(ser, ser, buffer_size=INPUT_BUFFER), encoding='latin1')
    return read_files(sio, args.input, args.output, args.base64)

def main():
    parser = argparse.ArgumentParser(description='Raw file transfer utility via serial interface.\n\nserial-transfer.py is useful for transferring files over a serial interface when the device has a very limited BusyBox and no serial file transfer protocols such as X-Modem.\nThe tool assumes a root shell is available on the serial interface. It uses very basic Linux commands, as well as pure BASH base64 encoding/decoding scripts for file transfers.\n\nWARNING: Because most devices use serial interfaces for debugging purposes (such as UART), random debugging output can appear at any time. While this does not affect the write functionality, file reads will most likely fail.', formatter_class=RawTextHelpFormatter)
    parser.add_argument('-V','--version', action='version', version='%(prog)s 1.0')
    subparsers = parser.add_subparsers()

    write_parser = subparsers.add_parser('write', help='Write files to target system')
    write_parser.add_argument('dev', help='Path to serial device')
    write_parser.add_argument('-b', '--base64', help='Use base64 encoding (smaller overhead, might not work on all systems)', action='store_true')
    write_parser.add_argument('-d', '--nodirstruct', help='Do not keep directory structure', action='store_true')
    write_parser.add_argument('-r', '--rate', help='Baud rate\t[Default: %d]' % DEFAULT_BAUD_RATE, default=DEFAULT_BAUD_RATE)
    write_parser.add_argument('-i', '--input', help='Input file/directory path (on local host)', default='')
    write_parser.add_argument('-o', '--output', help='Output file/directory path (on target system)\t[Default: %s]' % DEFAULT_RPATH, default=DEFAULT_RPATH)
    write_parser.add_argument('-c', '--chunk-size', help='Transfer chunk size (in bytes)\t[Default: %d]' % DEFAULT_CHUNK_SIZE, default=DEFAULT_CHUNK_SIZE)
    write_parser.add_argument('-p', '--perm', help='Octal permissions\t[Default: %s]' % DEFAULT_PERM, default=DEFAULT_PERM)
    write_parser.set_defaults(func=parse_write)

    read_parser = subparsers.add_parser('read', help='Read files from target system')
    read_parser.add_argument('dev', help='Path to serial device')
    read_parser.add_argument('-b', '--base64', help='Use base64 encoding (smaller overhead, might not work on all systems)', action='store_true')
    read_parser.add_argument('-r', '--rate', help='Baud rate\t[Default: %d]' % DEFAULT_BAUD_RATE, default=DEFAULT_BAUD_RATE)
    read_parser.add_argument('-i', '--input', help='Input file/directory path (on target system)', default='')
    read_parser.add_argument('-o', '--output', help='Output file/directory path (on local host)', default='./')
    read_parser.set_defaults(func=parse_read)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
   main()

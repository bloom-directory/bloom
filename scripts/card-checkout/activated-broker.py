#!/usr/bin/env python3
"""Exec the real Broker with the inherited loopback listeners it requires."""
import os
import sys
os.environ['LISTEN_PID'] = str(os.getpid())
os.environ['LISTEN_FDS'] = '2'
os.environ['LISTEN_FDNAMES'] = 'broker-ceremony-ipv4:broker-ceremony-ipv6'
os.execv(sys.argv[1], sys.argv[1:])

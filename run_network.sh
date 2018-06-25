#!/bin/sh

sudo fuser -k 6653/tcp
sudo mn -c
sudo python mininet_setup.py


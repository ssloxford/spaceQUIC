#!/bin/bash

echo Hostname: $(cat /etc/hostname)
cd /code/build/exe/cpu1
./core-cpu1

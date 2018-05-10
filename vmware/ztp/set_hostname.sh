#!/usr/bin/env bash

# execute uppon a first, sets a bootstrap vnf a hostname equal to a esxi UUID
NEW_HOSTNAME=$(/home/vmware/scripts/retrieve_esxi_uuid.py)
echo $NEW_HOSTNAME > /proc/sys/kernel/hostname
sed -i 's/127.0.1.1.*/127.0.1.1\t'"$NEW_HOSTNAME"'/g' /etc/hosts
echo $NEW_HOSTNAME > /etc/hostname
sudo hostnamectl set-hostname $NEW_HOSTNAME
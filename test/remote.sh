#!/bin/sh
set -ex
. ./test.rc

MSG="kilroy"

/sbin/ifconfig -a

sudo tshark -Qni lo -w ${CAP} port ${PORT} &
#sudo tcpdump -qlni lo -w ${CAP} port ${PORT} &
PID="$!"
sleep 5
ps fax  |grep -A3 tshark

../src/logger -u ${SOCK} ${MSG}

sleep 5
sudo kill -TERM ${PID}
wait ${PID}

tshark -d udp.port==${PORT},syslog -r ${CAP} | grep ${MSG}
rm ${CAP}


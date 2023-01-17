#!/bin/bash
#export LC_TIME=ko_KR.UTF-8
#export LC_MONETARY=ko_KR.UTF-8
export APACHE_RUN_DIR=/var/run/apache2
export APACHE_PID_FILE=/var/run/apache2/apache2.pid
#export JOURNAL_STREAM=8:3762294
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
#export INVOCATION_ID=7d822320d5054a7081314eed39a4e034
#export LC_ADDRESS=ko_KR.UTF-8
export APACHE_LOCK_DIR=/var/lock/apache2
#export LANG=C
#export LC_TELEPHONE=ko_KR.UTF-8
#export LC_NAME=ko_KR.UTF-8
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
#export LC_MEASUREMENT=ko_KR.UTF-8
export APACHE_LOG_DIR=/var/log/apache2
#export LC_IDENTIFICATION=ko_KR.UTF-8
#export PWD=/
#export LC_NUMERIC=ko_KR.UTF-8
#export LC_PAPER=ko_KR.UTF-8root

#sudo -E -H -u www-data bash -c '/usr/sbin/apache2 -k start'

/usr/sbin/apache2 -k stop





#!/bin/bash

cp Mail-Milter-Authentication/share/authentication_milter.init /etc/init.d/authentication_milter
#cp mail-dmarc.ini /etc/
#cp authentication_milter.json /etc/

cd Mail-Milter-Authentication
perl Makefile.PL
make
make install

/etc/init.d/authentication_milter restart

ps aux|grep authentication_milter
tail -f /var/log/mail.log


#!/bin/bash

cp init /etc/init.d/authentication_milter
#cp mail-dmarc.ini /etc/
cp authentication_milter.json /etc/

cd Mail-Milter-Authentication
perl Makefile.PL
make
make install

/etc/init.d/authentication_milter restart

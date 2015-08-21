Authentication Milter Docker
============================

Config
------

Configuration of Authentication Milter

A valid authentication_milter.json file should be created.

Configuration of DMARC

A valid mail-dmarc.ini file should be created, if using reporting this must include
database configuration for the reporting database (see section below).

These configuration files should be passed in using volumes.

Logs
----

Enable logtoerr in the authentication_milter.json configuration and do not set
the error_log setting to enable logs to be written to the STDERR stream.

Database
--------

If using DMARC, you will need to create and configure the DMARC reporting database.

DMARC Report Sending
--------------------

If using DMARC reporting, you will need to setup outgoing report emails.

If you have configured reporting to DKIM sign messages you will need to
pass in the private signing key using a volume.

TODO: A cron job to be automatically enabled if DMARC is enabled in config.

Public Suffix List Updates
--------------------------

The public suffix list file is currently used to validate DMARC domains, this file
is updated periodically if the DMARC module is enabled.
Place the psl_file in persistent storage to avoid redownloading each time the
container is run. The location of the file is specified in the mail-dmarc.ini
configuration file. In these examples we have placed this file in /data/

Connection to MTA
-----------------

To be written

Example execution
-----------------

`````
docker run --name=authentication_milter \
    -v /path/to/authentication_milter.json:/etc/authentication_milter.json \
    -v /path/to/mail-dmarc.ini:/etc/mail-dmarc.ini \
    -v /opt/data:/data/ \
    -p 12345:12345 \
    -it --rm \
    marcbradshaw/authentication_milter
`````


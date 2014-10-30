# ************************************************************
# Sequel Pro SQL dump
# Version 4096
#
# http://www.sequelpro.com/
# http://code.google.com/p/sequel-pro/
#
# Host: 127.0.0.2 (MySQL 5.5.30)
# Database: mail_dmarc
# Generation Time: 2013-05-17 07:47:45 +0000
# ************************************************************


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


# Dump of table author
# ------------------------------------------------------------

DROP TABLE IF EXISTS `author`;

CREATE TABLE `author` (
      `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
      `org_name` varchar(253) CHARACTER SET ascii NOT NULL DEFAULT '',
      `email`    varchar(255) CHARACTER SET ascii DEFAULT NULL,
      `extra_contact` varchar(255) CHARACTER SET ascii DEFAULT NULL,
      PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



# Dump of table domain
# ------------------------------------------------------------

DROP TABLE IF EXISTS `domain`;

CREATE TABLE `domain` (
      `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
      `domain` varchar(253) CHARACTER SET ascii NOT NULL DEFAULT '',
      PRIMARY KEY (`id`),
      UNIQUE KEY `domain` (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


DROP TABLE IF EXISTS `report_error`;

CREATE TABLE `report_error` (
      `report_id` int(11) unsigned NOT NULL,
      `error` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
      `time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      KEY `report_id` (`report_id`),
      CONSTRAINT `report_error_ibfk_1` FOREIGN KEY (`report_id`) REFERENCES `report` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


# Dump of table fk_disposition
# ------------------------------------------------------------

DROP TABLE IF EXISTS `fk_disposition`;

CREATE TABLE `fk_disposition` (
      `disposition` varchar(10) NOT NULL DEFAULT '',
      PRIMARY KEY (`disposition`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

LOCK TABLES `fk_disposition` WRITE;
/*!40000 ALTER TABLE `fk_disposition` DISABLE KEYS */;

INSERT INTO `fk_disposition` (`disposition`)
VALUES
    ('none'),
        ('quarantine'),
            ('reject');

            /*!40000 ALTER TABLE `fk_disposition` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table fk_disposition_reason
# ------------------------------------------------------------

DROP TABLE IF EXISTS `fk_disposition_reason`;

CREATE TABLE `fk_disposition_reason` (
      `type` varchar(24) NOT NULL DEFAULT '',
      PRIMARY KEY (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

LOCK TABLES `fk_disposition_reason` WRITE;
/*!40000 ALTER TABLE `fk_disposition_reason` DISABLE KEYS */;

INSERT INTO `fk_disposition_reason` (`type`)
VALUES
    ('forwarded'),
        ('local_policy'),
            ('mailing_list'),
                ('other'),
                    ('sampled_out'),
                        ('trusted_forwarder');

                        /*!40000 ALTER TABLE `fk_disposition_reason` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table fk_dkim_result
# ------------------------------------------------------------

DROP TABLE IF EXISTS `fk_dkim_result`;

CREATE TABLE `fk_dkim_result` (
      `result` varchar(9) NOT NULL DEFAULT '',
      PRIMARY KEY (`result`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

LOCK TABLES `fk_dkim_result` WRITE;
/*!40000 ALTER TABLE `fk_dkim_result` DISABLE KEYS */;

INSERT INTO `fk_dkim_result` (`result`)
VALUES
    ('fail'),
        ('neutral'),
            ('none'),
                ('pass'),
                    ('permerror'),
                        ('policy'),
                            ('temperror');

                            /*!40000 ALTER TABLE `fk_dkim_result` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table fk_spf_result
# ------------------------------------------------------------

DROP TABLE IF EXISTS `fk_spf_result`;

CREATE TABLE `fk_spf_result` (
      `result` varchar(9) NOT NULL DEFAULT '',
      PRIMARY KEY (`result`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

LOCK TABLES `fk_spf_result` WRITE;
/*!40000 ALTER TABLE `fk_spf_result` DISABLE KEYS */;

INSERT INTO `fk_spf_result` (`result`)
VALUES
    ('fail'),
        ('neutral'),
            ('none'),
                ('pass'),
                    ('permerror'),
                        ('softfail'),
                            ('temperror');

                            /*!40000 ALTER TABLE `fk_spf_result` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table fk_spf_scope
# ------------------------------------------------------------

DROP TABLE IF EXISTS `fk_spf_scope`;

CREATE TABLE `fk_spf_scope` (
      `scope` varchar(5) NOT NULL DEFAULT '',
      PRIMARY KEY (`scope`)
) ENGINE=InnoDB DEFAULT CHARSET=ascii;

LOCK TABLES `fk_spf_scope` WRITE;
/*!40000 ALTER TABLE `fk_spf_scope` DISABLE KEYS */;

INSERT INTO `fk_spf_scope` (`scope`)
VALUES
    ('helo'),
        ('mfrom');

        /*!40000 ALTER TABLE `fk_spf_scope` ENABLE KEYS */;
UNLOCK TABLES;


# Dump of table report
# ------------------------------------------------------------

DROP TABLE IF EXISTS `report`;

CREATE TABLE `report` (
      `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
      `begin` int(11) unsigned NOT NULL,
      `end` int(11) unsigned NOT NULL,
      `author_id` int(11) unsigned NOT NULL,
      `rcpt_domain_id` int(11) unsigned DEFAULT NULL,
      `from_domain_id` int(11) unsigned NOT NULL,
      `uuid` varchar(253) DEFAULT NULL,
      PRIMARY KEY (`id`),
      KEY `author_id` (`author_id`),
      KEY `from_domain_id` (`from_domain_id`),
      CONSTRAINT `report_ibfk_3` FOREIGN KEY (`from_domain_id`) REFERENCES `domain` (`id`) ON UPDATE CASCADE,
      CONSTRAINT `report_ibfk_1` FOREIGN KEY (`author_id`) REFERENCES `author` (`id`) ON DELETE NO ACTION ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;


# Dump of table report_policy_published
# ------------------------------------------------------------

DROP TABLE IF EXISTS `report_policy_published`;

CREATE TABLE `report_policy_published` (
      `report_id` int(11) unsigned NOT NULL,
      `adkim` char(1) DEFAULT NULL,
      `aspf` char(1) DEFAULT NULL,
      `p` varchar(10) DEFAULT NULL,
      `sp` varchar(10) DEFAULT NULL,
      `pct` tinyint(1) unsigned DEFAULT NULL,
      `rua` varchar(255) DEFAULT NULL,
      KEY `report_id` (`report_id`),
      CONSTRAINT `report_policy_published_ibfk_1` FOREIGN KEY (`report_id`) REFERENCES `report` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;



# Dump of table report_record
# ------------------------------------------------------------

DROP TABLE IF EXISTS `report_record`;

CREATE TABLE `report_record` (
      `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
      `report_id` int(11) unsigned NOT NULL,
      `source_ip` varbinary(16) NOT NULL DEFAULT '',
      `count` tinyint(2) unsigned DEFAULT NULL,
      `disposition` varchar(10) NOT NULL DEFAULT '',
      `dkim` char(4) NOT NULL DEFAULT '',
      `spf` char(4) NOT NULL DEFAULT '',
      `envelope_to_did` int(11) unsigned DEFAULT NULL,
      `envelope_from_did` int(11) unsigned DEFAULT NULL,
      `header_from_did` int(11) unsigned NOT NULL,
      PRIMARY KEY (`id`),
      KEY `report_id` (`report_id`),
      KEY `disposition` (`disposition`),
      CONSTRAINT `report_record_ibfk_2` FOREIGN KEY (`disposition`) REFERENCES `fk_disposition` (`disposition`) ON DELETE CASCADE ON UPDATE CASCADE,
      CONSTRAINT `report_record_ibfk_1` FOREIGN KEY (`report_id`) REFERENCES `report` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;



# Dump of table report_record_reason
# ------------------------------------------------------------

DROP TABLE IF EXISTS `report_record_reason`;

CREATE TABLE `report_record_reason` (
      `report_record_id` int(11) unsigned NOT NULL,
      `type` varchar(24) NOT NULL DEFAULT '',
      `comment` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
      KEY `report_record_id` (`report_record_id`),
      KEY `type` (`type`),
      CONSTRAINT `report_record_reason_ibfk_3` FOREIGN KEY (`report_record_id`) REFERENCES `report_record` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
      CONSTRAINT `report_record_reason_ibfk_4` FOREIGN KEY (`type`) REFERENCES `fk_disposition_reason` (`type`) ON DELETE NO ACTION ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;



# Dump of table report_record_dkim
# ------------------------------------------------------------

DROP TABLE IF EXISTS `report_record_dkim`;

CREATE TABLE `report_record_dkim` (
      `report_record_id` int(11) unsigned NOT NULL,
      `domain_id` int(11) unsigned NOT NULL,
      `selector` varchar(253) DEFAULT NULL,
      `result` varchar(9) NOT NULL DEFAULT '',
      `human_result` varchar(64) DEFAULT NULL,
      KEY `report_record_id` (`report_record_id`),
      KEY `result` (`result`),
      CONSTRAINT `report_record_dkim_ibfk_2` FOREIGN KEY (`result`) REFERENCES `fk_dkim_result` (`result`),
      CONSTRAINT `report_record_dkim_ibfk_1` FOREIGN KEY (`report_record_id`) REFERENCES `report_record` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;



# Dump of table report_record_spf
# ------------------------------------------------------------

DROP TABLE IF EXISTS `report_record_spf`;

CREATE TABLE `report_record_spf` (
      `report_record_id` int(11) unsigned NOT NULL,
      `domain_id` int(11) unsigned NOT NULL,
      `scope` varchar(5) DEFAULT NULL,
      `result` varchar(9) NOT NULL DEFAULT '',
      KEY `report_record_id` (`report_record_id`),
      KEY `scope` (`scope`),
      KEY `result` (`result`),
      CONSTRAINT `report_record_spf_ibfk_1` FOREIGN KEY (`report_record_id`) REFERENCES `report_record` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
      CONSTRAINT `report_record_spf_ibfk_2` FOREIGN KEY (`scope`) REFERENCES `fk_spf_scope` (`scope`) ON DELETE CASCADE ON UPDATE CASCADE,
      CONSTRAINT `report_record_spf_ibfk_3` FOREIGN KEY (`result`) REFERENCES `fk_spf_result` (`result`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=ascii;




/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

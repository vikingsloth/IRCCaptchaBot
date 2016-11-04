CREATE TABLE `captcha` (
  `user_key` varchar(32) NOT NULL,
  `ident_host` varchar(128) NOT NULL,
  `nick` varchar(20) NOT NULL,
  `post_ip` varchar(15) DEFAULT NULL,
  `start` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`user_key`)
);
CREATE TABLE `captcha_archive` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `user_key` varchar(32) NOT NULL,
  `ident_host` varchar(128) NOT NULL,
  `nick` varchar(20) NOT NULL,
  `post_ip` varchar(15) DEFAULT NULL,
  `start` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `completed` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`id`)
);
CREATE TABLE `exceptions` (
  `ident_host` varchar(128) NOT NULL,
  `user_key` varchar(32) NOT NULL,
  `first` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `last` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`ident_host`),
  KEY `ident_host_idx` (`ident_host`)
);

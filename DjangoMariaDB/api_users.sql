CREATE TABLE `api_users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user` varchar(250) NOT NULL DEFAULT '',
  `password` varchar(250) NOT NULL DEFAULT '',
  `api_key` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

INSERT INTO `api_users` (`id`, `user`, `password`) VALUES
('0', 'marcochong.27@gmail.com', 'pbkdf2_sha256$180000$PiTBENEFhDD8$p/ONz+pyXenUA+ar5ur5drSGCWqrBMRertnMYMtwr3w=');

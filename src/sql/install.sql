DROP TABLE IF EXISTS `#__webservices_credentials`;

CREATE TABLE `#__webservices_credentials`
(
    `credentials_id`            int(11)      NOT NULL AUTO_INCREMENT,
    `client_id`                 varchar(255) NOT NULL DEFAULT '',
    `client_secret`             varchar(255) NOT NULL DEFAULT '',
    `client_ip`                 varchar(255) NOT NULL,
    `temporary_token`           varchar(255) NOT NULL,
    `access_token`              varchar(255) NOT NULL DEFAULT '',
    `refresh_token`             varchar(255) NOT NULL DEFAULT '',
    `resource_uri`              varchar(255) NOT NULL DEFAULT '',
    `type`                      varchar(255) NOT NULL DEFAULT '',
    `callback_url`              varchar(255) NOT NULL DEFAULT '',
    `resource_owner_id`         int(11)      NOT NULL DEFAULT '0',
    `expiration_date`           datetime              DEFAULT NULL,
    `temporary_expiration_date` datetime              DEFAULT NULL,
    PRIMARY KEY (`credentials_id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8;

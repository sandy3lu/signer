CREATE TABLE `key`(
`id` int NOT NULL AUTO_INCREMENT COMMENT '自增id（常量编码）' ,
`user_id` varchar(64) not null COMMENT '申请创建key的用户id',
`key_type` ENUM('SM2Priv','SM2Pub','SM4','RSA2048Priv','RSA2048Pub','AES128') not null COMMENT 'key的类型',
`content` varchar(2048) not null COMMENT 'key的内容',
`related_key` int default null COMMENT 'private key关联的public key',
`signature` varchar(128) default null COMMENT 'key的签名值',
`sign_key` int default null COMMENT '签名用的key',
`create_time` datetime COMMENT '创建时间',
PRIMARY KEY (`id`)
) ENGINE=InnoDB  AUTO_INCREMENT=22 DEFAULT CHARSET=utf8 COMMENT='key管理表';
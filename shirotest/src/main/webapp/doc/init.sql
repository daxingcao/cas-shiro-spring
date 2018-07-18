/*
Navicat MySQL Data Transfer

Source Server         : usercenternew
Source Server Version : 50623
Source Host           : 172.16.0.26:3306
Source Database       : test

Target Server Type    : MYSQL
Target Server Version : 50623
File Encoding         : 65001

Date: 2018-07-13 18:22:43
*/

-- ----------------------------
-- Table structure for `db_user_role`
-- ----------------------------
DROP TABLE IF EXISTS `db_user_role`;
CREATE TABLE `db_user_role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `role_id` bigint(20) DEFAULT NULL COMMENT '角色id',
  `user_id` bigint(20) DEFAULT NULL COMMENT '用户id',
  `create_dt` datetime DEFAULT NULL COMMENT '创建时间',
  `update_dt` datetime DEFAULT NULL COMMENT '更新时间',
  `del` int(11) DEFAULT NULL COMMENT '是否删除:0.未删除;1.已删除',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8 COMMENT='用户-角色关联表';

-- ----------------------------
-- Records of db_user_role
-- ----------------------------
INSERT INTO `db_user_role` VALUES ('1', '1', '2', '2018-07-10 17:24:31', null, '0');

-- ----------------------------
-- Table structure for `login_user`
-- ----------------------------
DROP TABLE IF EXISTS `login_user`;
CREATE TABLE `login_user` (
  `id` bigint(19) NOT NULL AUTO_INCREMENT COMMENT '用户登录表ID',
  `USERNAME` varchar(30) NOT NULL COMMENT '用户名',
  `PASSWORD` varchar(50) NOT NULL COMMENT '登录密码',
  `LAST_DATE` date DEFAULT NULL COMMENT '上次登录时间',
  `CREATE_DATE` date DEFAULT NULL COMMENT '创建时间',
  `UPDATE_DATE` date DEFAULT NULL COMMENT '更新时间',
  `LOGIN_STATUS` int(4) DEFAULT '0' COMMENT '登录状态, 0.未登录, 1.已登录',
  `USER_ID` int(4) DEFAULT NULL COMMENT '对应数据信息表id',
  `HEAD_FILE_ID` int(11) DEFAULT NULL COMMENT '头像文件id,对应sysfile表id',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COMMENT='用户登录表';

-- ----------------------------
-- Records of login_user
-- ----------------------------
INSERT INTO `login_user` VALUES ('1', 'lisi', 'E10ADC3949BA59ABBE56E057F20F883E', '2018-02-05', '2018-02-02', '2018-02-05', '0', null, '135');
INSERT INTO `login_user` VALUES ('2', 'zhangsan', 'E10ADC3949BA59ABBE56E057F20F883E', '2018-04-26', '2018-04-26', '2018-04-26', '0', null, null);
INSERT INTO `login_user` VALUES ('3', 'wanger', 'E10ADC3949BA59ABBE56E057F20F883E', '2018-05-30', '2018-05-30', '2018-05-30', '0', null, null);

-- ----------------------------
-- Table structure for `db_auth_role`
-- ----------------------------
DROP TABLE IF EXISTS `db_auth_role`;
CREATE TABLE `db_auth_role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `auth_name` varchar(100) DEFAULT NULL COMMENT '权限名',
  `auth_url` varchar(100) DEFAULT NULL COMMENT '权限url',
  `role_id` bigint(20) DEFAULT NULL COMMENT '角色id',
  `create_dt` datetime DEFAULT NULL COMMENT '创建时间',
  `update_dt` datetime DEFAULT NULL COMMENT '更新时间',
  `del` int(11) DEFAULT NULL COMMENT '是否删除:0.未删除,1.已删除',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COMMENT='权限-角色关联表';

-- ----------------------------
-- Records of db_auth_role
-- ----------------------------
INSERT INTO `db_auth_role` VALUES ('1', '查看', 'test:view', '1', '2018-07-10 17:45:47', null, '0');
INSERT INTO `db_auth_role` VALUES ('2', '更新', 'test:update', '1', '2018-07-10 17:46:35', null, '0');
INSERT INTO `db_auth_role` VALUES ('3', '删除', 'test:del', '1', '2018-07-10 17:46:50', null, '0');

-- ----------------------------
-- Table structure for `USER_INFO`
-- ----------------------------
DROP TABLE IF EXISTS `USER_INFO`;
CREATE TABLE `USER_INFO` (
  `INFO_ID` int(11) NOT NULL AUTO_INCREMENT COMMENT '用户信息ID',
  `USER_NAME` varchar(50) DEFAULT NULL COMMENT '用户真实姓名',
  `USER_AGE` int(11) DEFAULT NULL COMMENT '用户年龄',
  `USER_GANDER` int(4) DEFAULT NULL COMMENT '用户性别 0 未知 1 男 2 女',
  `USER_ADDRESS` varchar(200) DEFAULT NULL COMMENT '用户居住地址',
  `USER_QQ` varchar(20) DEFAULT NULL COMMENT '用户QQ号',
  `USER_WECHAT` varchar(20) DEFAULT NULL COMMENT '用户微信号',
  `USER_MOBILE` varchar(20) DEFAULT NULL COMMENT '用户手机',
  PRIMARY KEY (`INFO_ID`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COMMENT='用户信息表';

-- ----------------------------
-- Records of USER_INFO
-- ----------------------------
INSERT INTO `USER_INFO` VALUES ('1', 'zhangsan', '18', '0', 'asd', '123213213', '412321331', '12312312312');
INSERT INTO `USER_INFO` VALUES ('2', 'hery', '20', '1', 'shanghai', null, null, null);
INSERT INTO `USER_INFO` VALUES ('3', 'hery', '20', '1', 'shanghai', null, null, null);

-- ----------------------------
-- Table structure for `db_role`
-- ----------------------------
DROP TABLE IF EXISTS `db_role`;
CREATE TABLE `db_role` (
  `role_id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '角色id',
  `role_name` varchar(100) DEFAULT NULL COMMENT '角色名',
  `role_remark` varchar(100) DEFAULT NULL COMMENT '角色描述',
  `create_dt` datetime DEFAULT NULL COMMENT '创建时间',
  `update_dt` datetime DEFAULT NULL COMMENT '更新时间',
  `del` int(11) DEFAULT NULL COMMENT '是否删除:0,未删除;1已删除',
  PRIMARY KEY (`role_id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8 COMMENT='角色信息表';

-- ----------------------------
-- Records of db_role
-- ----------------------------
INSERT INTO `db_role` VALUES ('1', 'superadmin', '超级管理员', '2018-07-10 17:18:01', null, '0');
INSERT INTO `db_role` VALUES ('2', 'admin', '系统管理员', '2018-07-10 17:18:15', null, '0');
INSERT INTO `db_role` VALUES ('3', 'user', '用户', '2018-07-10 17:18:29', null, '0');

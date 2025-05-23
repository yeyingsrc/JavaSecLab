/*
 Navicat Premium Dump SQL

 Source Server         : mysql_docker_mac
 Source Server Type    : MySQL
 Source Server Version : 80200 (8.2.0)
 Source Host           : localhost:13306
 Source Schema         : JavaSecLab

 Target Server Type    : MySQL
 Target Server Version : 80200 (8.2.0)
 File Encoding         : 65001

 Date: 23/03/2025 17:52:40
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for objects
-- ----------------------------
DROP TABLE IF EXISTS `objects`;
CREATE TABLE `objects` (
  `id` int NOT NULL,
  `malicious_object` blob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- ----------------------------
-- Records of objects
-- ----------------------------
BEGIN;
INSERT INTO `objects` (`id`, `malicious_object`) VALUES (1, 0xACED000573720034746F702E7768676F6A702E6D6F64756C65732E737072696E67626F6F742E656E746974792E4D616C6963696F75734F626A656374C007A841C29C41060200014C0007636F6D6D616E647400124C6A6176612F6C616E672F537472696E673B78707400126F70656E202D612043616C63756C61746F72);
COMMIT;

-- ----------------------------
-- Table structure for sqli
-- ----------------------------
DROP TABLE IF EXISTS `sqli`;
CREATE TABLE `sqli` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名',
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '密码',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of sqli
-- ----------------------------
BEGIN;
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (1, 'admin', 'admin');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (2, 'admin123', 'admin123');
INSERT INTO `sqli` (`id`, `username`, `password`) VALUES (3, 'test', 'test');
COMMIT;

-- ----------------------------
-- Table structure for user
-- ----------------------------
DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '用户名',
  `password` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '密码',
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of user
-- ----------------------------
BEGIN;
INSERT INTO `user` (`username`, `password`) VALUES ('123', '123');
INSERT INTO `user` (`username`, `password`) VALUES ('admin', 'admin');
INSERT INTO `user` (`username`, `password`) VALUES ('test', 'test');
COMMIT;

-- ----------------------------
-- Table structure for xss
-- ----------------------------
DROP TABLE IF EXISTS `xss`;
CREATE TABLE `xss` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键id',
  `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '插入内容',
  `ua` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT 'User-Agent',
  `date` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '插入时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=85 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of xss
-- ----------------------------
BEGIN;
INSERT INTO `xss` (`id`, `content`, `ua`, `date`) VALUES (65, '123<u>A</u>123', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', '2024-06-30 23:36:48');
INSERT INTO `xss` (`id`, `content`, `ua`, `date`) VALUES (66, '123<a href=javascript:alert(/xss/)>Click Me</a>123', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', '2024-06-30 23:37:02');
INSERT INTO `xss` (`id`, `content`, `ua`, `date`) VALUES (69, '123', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0', '2024-07-21 10:07:34');
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;

-- MySQL dump 10.13  Distrib 8.3.0, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: unified_certification
-- ------------------------------------------------------
-- Server version	8.3.0

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `authorities`
--

DROP TABLE IF EXISTS `authorities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `authorities` (
  `username` varchar(50) NOT NULL,
  `authority` varchar(50) NOT NULL,
  UNIQUE KEY `ix_auth_username` (`username`,`authority`),
  CONSTRAINT `fk_authorities_users` FOREIGN KEY (`username`) REFERENCES `users` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `authorities`
--

LOCK TABLES `authorities` WRITE;
/*!40000 ALTER TABLE `authorities` DISABLE KEYS */;
INSERT INTO `authorities` VALUES ('user','ROLE_ADMIN');
/*!40000 ALTER TABLE `authorities` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `oauth2_authorization`
--

DROP TABLE IF EXISTS `oauth2_authorization`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth2_authorization` (
  `id` varchar(100) NOT NULL,
  `registered_client_id` varchar(100) NOT NULL,
  `principal_name` varchar(200) NOT NULL,
  `authorization_grant_type` varchar(100) NOT NULL,
  `authorized_scopes` varchar(1000) DEFAULT NULL,
  `attributes` blob,
  `state` varchar(500) DEFAULT NULL,
  `authorization_code_value` blob,
  `authorization_code_issued_at` timestamp NULL DEFAULT NULL,
  `authorization_code_expires_at` timestamp NULL DEFAULT NULL,
  `authorization_code_metadata` blob,
  `access_token_value` blob,
  `access_token_issued_at` timestamp NULL DEFAULT NULL,
  `access_token_expires_at` timestamp NULL DEFAULT NULL,
  `access_token_metadata` blob,
  `access_token_type` varchar(100) DEFAULT NULL,
  `access_token_scopes` varchar(1000) DEFAULT NULL,
  `oidc_id_token_value` blob,
  `oidc_id_token_issued_at` timestamp NULL DEFAULT NULL,
  `oidc_id_token_expires_at` timestamp NULL DEFAULT NULL,
  `oidc_id_token_metadata` blob,
  `refresh_token_value` blob,
  `refresh_token_issued_at` timestamp NULL DEFAULT NULL,
  `refresh_token_expires_at` timestamp NULL DEFAULT NULL,
  `refresh_token_metadata` blob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `oauth2_authorization`
--

LOCK TABLES `oauth2_authorization` WRITE;
/*!40000 ALTER TABLE `oauth2_authorization` DISABLE KEYS */;
INSERT INTO `oauth2_authorization` VALUES ('1dec9140-4289-41ff-96b6-a9d5deb8edb8','08daa077-daf2-4498-9ebf-f74bfe59ff0e','user','authorization_code','openid,message.read,message.write',_binary '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\":{\"@class\":\"org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest\",\"authorizationUri\":\"http://localhost:9000/oauth2/authorize\",\"authorizationGrantType\":{\"value\":\"authorization_code\"},\"responseType\":{\"value\":\"code\"},\"clientId\":\"messaging-client\",\"redirectUri\":\"http://127.0.0.1:8000/login/oauth2/code/messaging-client-oidc\",\"scopes\":[\"java.util.Collections$UnmodifiableSet\",[\"openid\",\"message.read\",\"message.write\"]],\"state\":\"BWw60RgchjXvxXeOGCIzDrFl61bOtIOMCwOlW6YTNPo=\",\"additionalParameters\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"nonce\":\"G5KNw-3lXWhinzq0DrHg4bClnBa6Y2YDrMRf9uqo034\"},\"authorizationRequestUri\":\"http://localhost:9000/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid%20message.read%20message.write&state=BWw60RgchjXvxXeOGCIzDrFl61bOtIOMCwOlW6YTNPo%3D&redirect_uri=http://127.0.0.1:8000/login/oauth2/code/messaging-client-oidc&nonce=G5KNw-3lXWhinzq0DrHg4bClnBa6Y2YDrMRf9uqo034\",\"attributes\":{\"@class\":\"java.util.Collections$UnmodifiableMap\"}},\"java.security.Principal\":{\"@class\":\"org.springframework.security.authentication.UsernamePasswordAuthenticationToken\",\"authorities\":[\"java.util.Collections$UnmodifiableRandomAccessList\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_ADMIN\"}]],\"details\":{\"@class\":\"org.springframework.security.web.authentication.WebAuthenticationDetails\",\"remoteAddress\":\"0:0:0:0:0:0:0:1\",\"sessionId\":\"0C6622AC376A0FDD01DEBA2553205E06\"},\"authenticated\":true,\"principal\":{\"@class\":\"org.springframework.security.core.userdetails.User\",\"password\":null,\"username\":\"user\",\"authorities\":[\"java.util.Collections$UnmodifiableSet\",[{\"@class\":\"org.springframework.security.core.authority.SimpleGrantedAuthority\",\"authority\":\"ROLE_ADMIN\"}]],\"accountNonExpired\":true,\"accountNonLocked\":true,\"credentialsNonExpired\":true,\"enabled\":true},\"credentials\":null}}',NULL,_binary '4q3Y_BVXuQGI8FFJh1pdzEO-DYHofOEqweqlFtWUZ5wzgR2OFP5leuuG6MQt_WYMeA4gxVoRzpFzYXBKjEc5J4h8xzGxEGOJtw90Ez_JcXSq0qowkgAIIx963ZToQZsW','2024-04-08 23:46:14','2024-04-08 23:51:14',_binary '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":true}',_binary 'eyJraWQiOiJmMTlkMmQ3ZC0zNDIyLTQ2YzctYmZhOS02YWYzMWY2ODUxOGIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTcxMjY0ODc3Mywic2NvcGUiOlsib3BlbmlkIiwibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE3MTI2NTU5NzMsImlhdCI6MTcxMjY0ODc3M30.jnYPy9onvaNdCqXGAMqJbBlOptML_d3lg57C3-JPXAAp_CRSGHRP2l4zZ3dpXVNSUK7NEbYSiycXzmIp9sA_-I3PW64OCAmJAUliCm2twsEaL4bBwxKvzdAGRHH_bAVUJsFLDaCME_H7G04w4zQ22y_7jxkYD0MltmBVO08_7AYlibbC7I-hYdyPFEWFpFNkM_dDDrdNqDsJvyxVUEjxFVDiDKuxbEhwJ3VZM3bfqdCHXIlVCXRjg6bJhcS2m3_1M2_gBjgSy_4tuyVl24ZbjumV6QClE542pTfBxQgn7PkKNk_skxMetIoJPkYSCycl8iPis65-CiPcF81pQBVh0A','2024-04-08 23:46:14','2024-04-09 01:46:14',_binary '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"nbf\":[\"java.time.Instant\",1712648773.958000000],\"scope\":[\"java.util.Collections$UnmodifiableSet\",[\"openid\",\"message.read\",\"message.write\"]],\"iss\":[\"java.net.URL\",\"http://localhost:9000\"],\"exp\":[\"java.time.Instant\",1712655973.958000000],\"iat\":[\"java.time.Instant\",1712648773.958000000]},\"metadata.token.invalidated\":false}','Bearer','openid,message.read,message.write',_binary 'eyJraWQiOiJmMTlkMmQ3ZC0zNDIyLTQ2YzctYmZhOS02YWYzMWY2ODUxOGIiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsImF6cCI6Im1lc3NhZ2luZy1jbGllbnQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE3MTI2NTA1NzMsImlhdCI6MTcxMjY0ODc3Mywibm9uY2UiOiJHNUtOdy0zbFhXaGluenEwRHJIZzRiQ2xuQmE2WTJZRHJNUmY5dXFvMDM0In0.IXNc7wBTR9n66vghyONs-CsgH-hv9Ydd5Lx1FQjeXnE7f09hGDSZQ0VQf-0CsqSAorkaiIIBmFz0Uy7GKaW0mlJBC9VvJf5CQbL7GS9q5z-BUXdas-Whq31Y5HXArWiJYSKXEN0o0hf3toPJBjdQ8iaEeaCMCsdDRxBNdr88LbQH1S_TuNzdkkC7pY4uYSjEy6f3BLbY2trwHd4QCqTabFDM-7Ibd8GDULTKuGYTOp1DsGJDbYdLNseDQQWryEU7itX-vNAxeS-Nz17GR33kGdJL_NgBxC4YVqVC9uzySKhRdTGYjM1BPmfp9XtxVgRxklBrucX7I5RlcQwD6NbGDQ','2024-04-08 23:46:14','2024-04-09 00:16:14',_binary '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.claims\":{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"sub\":\"user\",\"aud\":[\"java.util.Collections$SingletonList\",[\"messaging-client\"]],\"azp\":\"messaging-client\",\"iss\":[\"java.net.URL\",\"http://localhost:9000\"],\"exp\":[\"java.time.Instant\",1712650573.973000000],\"iat\":[\"java.time.Instant\",1712648773.973000000],\"nonce\":\"G5KNw-3lXWhinzq0DrHg4bClnBa6Y2YDrMRf9uqo034\"},\"metadata.token.invalidated\":false}',_binary '_N6vXUNsY6LltjUgQEnP_7-mYMmMwuyUNG1avjAIWIT8f5h_cHB6U1U1RuE8JpJX2U1QSrSrktpechE9DhotpdZ6Oo0AXt_J7p8f5EncMLs0i6DFST_YgR8mpPBN7PAy','2024-04-08 23:46:14','2024-05-08 23:46:14',_binary '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"metadata.token.invalidated\":false}');
/*!40000 ALTER TABLE `oauth2_authorization` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `oauth2_authorization_consent`
--

DROP TABLE IF EXISTS `oauth2_authorization_consent`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth2_authorization_consent` (
  `registered_client_id` varchar(100) NOT NULL,
  `principal_name` varchar(200) NOT NULL,
  `authorities` varchar(1000) NOT NULL,
  PRIMARY KEY (`registered_client_id`,`principal_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `oauth2_authorization_consent`
--

LOCK TABLES `oauth2_authorization_consent` WRITE;
/*!40000 ALTER TABLE `oauth2_authorization_consent` DISABLE KEYS */;
INSERT INTO `oauth2_authorization_consent` VALUES ('08daa077-daf2-4498-9ebf-f74bfe59ff0e','user','SCOPE_openid,SCOPE_message.read,SCOPE_message.write');
/*!40000 ALTER TABLE `oauth2_authorization_consent` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `oauth2_registered_client`
--

DROP TABLE IF EXISTS `oauth2_registered_client`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `oauth2_registered_client` (
  `id` varchar(100) NOT NULL,
  `client_id` varchar(100) NOT NULL,
  `client_id_issued_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_secret` varchar(200) DEFAULT NULL,
  `client_secret_expires_at` timestamp NULL DEFAULT NULL,
  `client_name` varchar(200) NOT NULL,
  `client_authentication_methods` varchar(1000) NOT NULL,
  `authorization_grant_types` varchar(1000) NOT NULL,
  `redirect_uris` varchar(1000) DEFAULT NULL,
  `scopes` varchar(1000) NOT NULL,
  `client_settings` varchar(2000) NOT NULL,
  `token_settings` varchar(2000) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `oauth2_registered_client`
--

LOCK TABLES `oauth2_registered_client` WRITE;
/*!40000 ALTER TABLE `oauth2_registered_client` DISABLE KEYS */;
INSERT INTO `oauth2_registered_client` VALUES ('08daa077-daf2-4498-9ebf-f74bfe59ff0e','messaging-client','2024-03-26 21:09:09','$2a$10$7PuiUROTHGbzs7AAikUKEOMTtTqwyc9K4hAQwb1tfJcu9E9bf7opS',NULL,'08daa077-daf2-4498-9ebf-f74bfe59ff0e','client_secret_basic','refresh_token,password,client_credentials,authorization_code','http://127.0.0.1:8000/login/oauth2/code/messaging-client-oidc','openid,profile,message.read,message.write','{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.client.require-proof-key\":false,\"settings.client.require-authorization-consent\":true}','{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.token.reuse-refresh-tokens\":true,\"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],\"settings.token.access-token-time-to-live\":[\"java.time.Duration\",7200.000000000],\"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},\"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",2592000.000000000],\"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000]}');
/*!40000 ALTER TABLE `oauth2_registered_client` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `username` varchar(50) NOT NULL,
  `PASSWORD` varchar(500) NOT NULL,
  `enabled` tinyint(1) NOT NULL,
  PRIMARY KEY (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES ('user','$2a$10$h.knqDIsZ1hf5FpCiobcyu5a2nZ1gYFZvpmCsZmm/W6vd0TiFaIpS',1);
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-04-09 15:59:28

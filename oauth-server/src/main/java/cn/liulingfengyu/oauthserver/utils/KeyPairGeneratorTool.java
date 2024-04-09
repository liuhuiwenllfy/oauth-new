package cn.liulingfengyu.oauthserver.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyPairGeneratorTool {

    public static void generateKeyPairAndSaveToPem(String outputDirectory, String publicKeyFileName, String privateKeyFileName) throws Exception {
        // 生成密钥对生成器实例
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        // 生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // 保存公钥到PEM文件
        savePublicKeyToPem(outputDirectory, publicKeyFileName, keyPair.getPublic());
        // 保存私钥到PEM文件
        savePrivateKeyToPem(outputDirectory, privateKeyFileName, keyPair.getPrivate());
    }

    private static void savePublicKeyToPem(String outputDirectory, String fileName, PublicKey publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(publicKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // 获取公钥实例
        PublicKey publicKeyInstance = keyFactory.generatePublic(keySpecX509);

        String pemPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(keySpecX509.getEncoded()) +
                "\n-----END PUBLIC KEY-----";

        try (FileWriter writer = new FileWriter(outputDirectory + "/" + fileName)) {
            writer.write(pemPublicKey);
        }
    }

    private static void savePrivateKeyToPem(String outputDirectory, String fileName, PrivateKey privateKey) throws InvalidKeySpecException, IOException, NoSuchAlgorithmException {
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // 获取私钥实例
        PrivateKey privateKeyInstance = keyFactory.generatePrivate(keySpecPKCS8);

        String pemPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(keySpecPKCS8.getEncoded()) +
                "\n-----END PRIVATE KEY-----";

        try (FileWriter writer = new FileWriter(outputDirectory + "/" + fileName)) {
            writer.write(pemPrivateKey);
        }
    }

    public static void main(String[] args) {
        try {
            String outputDir = "F:\\IdeaProjects\\oauth-authorization-server-new\\src\\main\\resources\\keys"; // 指定输出目录
            generateKeyPairAndSaveToPem(outputDir, "public_key.pem", "private_key.pem");
            System.out.println("密钥对已成功生成并保存到 " + outputDir + " 目录下。");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
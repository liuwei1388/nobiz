package com.nobiz.common.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RsaUtils {

    private static final Logger LOG = LoggerFactory.getLogger(RsaUtils.class);

    private static volatile Map<String, String> keyMap = new HashMap<>();

    public static String getPublicKey() {
        String publicKey = keyMap.get("public");
        if (publicKey == null) {
            synchronized (keyMap.getClass()) {
                if (publicKey == null) {
                    try {
                        genKeyPair();
                        publicKey = keyMap.get("public");
                    } catch (NoSuchAlgorithmException e) {
                        LOG.error("", e);
                    }
                }
            }
        }
        return publicKey;
    }

    private static String getPrivateKey() {
        String privateKey = keyMap.get("private");
        if (privateKey == null) {
            LOG.error("");
        }
        return privateKey;
    }

    private static void genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        keyPairGenerator.initialize(1024, new SecureRandom());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPrivateKey aPrivate = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey aPublic = (RSAPublicKey) keyPair.getPublic();

        String publicKeyString = new String(Base64.getEncoder().encode(aPublic.getEncoded()));
        String privateKeyString = new String(Base64.getEncoder().encode(aPrivate.getEncoded()));


        keyMap.put("public", publicKeyString);
        keyMap.put("private", privateKeyString);
    }

    public static String encrypt(String str, String publicKey) throws Exception {
        byte[] decode = Base64.getDecoder().decode(publicKey);
        RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decode));

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        String outStr  = Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        return outStr;
    }

    /**
     * RSA私钥解密
     *
     * @param str 加密字符串
     * @return 铭文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str) {
        String outStr = "";
        //64位解码加密后的字符串
        byte[] inputByte = new byte[0];
        try {
            inputByte = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));

            //base64编码的私钥
            byte[] decoded = Base64.getDecoder().decode(getPrivateKey());
            RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
            //RSA解密
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            outStr = new String(cipher.doFinal(inputByte));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            LOG.error("未找到找到指定算法", e);
        } catch (InvalidKeyException e) {
            LOG.error("无效的秘钥", e);
        } catch (NoSuchPaddingException e) {
            LOG.error("请求特定填充机制, 但该环境中未提供时", e);
        } catch (BadPaddingException e) {
            LOG.error("预期对输入数据使用特定填充机制, 但未正确填充数据", e);
        } catch (InvalidKeySpecException e) {
            LOG.error("无效的密钥规范", e);
        } catch (IllegalBlockSizeException e) {
            LOG.error("非法的块大小", e);
        }
        return outStr;
    }

}

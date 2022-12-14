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
     * RSA????????????
     *
     * @param str ???????????????
     * @return ??????
     * @throws Exception ??????????????????????????????
     */
    public static String decrypt(String str) {
        String outStr = "";
        //64??????????????????????????????
        byte[] inputByte = new byte[0];
        try {
            inputByte = Base64.getDecoder().decode(str.getBytes(StandardCharsets.UTF_8));

            //base64???????????????
            byte[] decoded = Base64.getDecoder().decode(getPrivateKey());
            RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
            //RSA??????
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            outStr = new String(cipher.doFinal(inputByte));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            LOG.error("???????????????????????????", e);
        } catch (InvalidKeyException e) {
            LOG.error("???????????????", e);
        } catch (NoSuchPaddingException e) {
            LOG.error("????????????????????????, ???????????????????????????", e);
        } catch (BadPaddingException e) {
            LOG.error("?????????????????????????????????????????????, ????????????????????????", e);
        } catch (InvalidKeySpecException e) {
            LOG.error("?????????????????????", e);
        } catch (IllegalBlockSizeException e) {
            LOG.error("??????????????????", e);
        }
        return outStr;
    }

}

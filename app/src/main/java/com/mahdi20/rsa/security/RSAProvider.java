package com.mahdi20.rsa.security;



import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;


public class RSAProvider {

    public static final String KEY_ALGORITHM = "RSA";
    public static int KEYSIZE = 1024;
    public static int decodeLen = KEYSIZE / 8;
    public static int encodeLen = 110;//(DEFAULT_KEY_SIZE / 8) - 11;
    private static final String PUBLIC_KEY = "publicKey";
    private static final String PRIVATE_KEY = "privateKey";
    private static final String MODULES = "RSAModules";

    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    public static Map<String, Object> generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(KEYSIZE);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        BigInteger modules = privateKey.getModulus();

        Map<String, Object> keys = new HashMap<String, Object>(3);
        keys.put(PUBLIC_KEY, publicKey);
        keys.put(PRIVATE_KEY, privateKey);
        keys.put(MODULES, modules);
        return keys;
    }

    public static byte[] getModulesBytes(Map<String, Object> keys) {
        BigInteger big = (BigInteger) keys.get(MODULES);
        return big.toByteArray();
    }

    public static String getPrivateKeyBytes(Map<String, Object> keys) throws Exception {
        Key key = (Key) keys.get(PRIVATE_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    public static String getPublicKeyBytes(Map<String, Object> keys) throws Exception {
        Key key = (Key) keys.get(PUBLIC_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    public static String sign(byte[] data, String privateKey) throws Exception {
        PrivateKey privateK = loadPrivateKey(privateKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }

    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        PublicKey publicK = loadPublicKey(publicKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));
    }

    public static byte[] encryptPrivateKey(byte[] encryptedData, String key) throws Exception {
        if (encryptedData == null) {
            throw new IllegalArgumentException("Input encryption data is null");
        }
        byte[] encode = new byte[]{};
        for (int i = 0; i < encryptedData.length; i += encodeLen) {
            byte[] subarray = ArrayUtils.subarray(encryptedData, i, i + encodeLen);
            byte[] doFinal = encryptByPrivateKey(subarray, key);
            encode = ArrayUtils.addAll(encode, doFinal);
        }
        return encode;
    }

    public static byte[] decryptPublicKey(byte[] encode, String key) throws Exception {
        if (encode == null) {
            throw new IllegalArgumentException("Input encryption data is null");
        }
        byte[] buffers = new byte[]{};
        for (int i = 0; i < encode.length; i += decodeLen) {
            byte[] subarray = ArrayUtils.subarray(encode, i, i + decodeLen);
            byte[] doFinal = decryptByPublicKey(subarray, key);
            buffers = ArrayUtils.addAll(buffers, doFinal);
        }
        return buffers;
    }

    public static byte[] encryptPublicKey(byte[] encryptedData, String key) throws Exception {
        if (encryptedData == null) {
            throw new IllegalArgumentException("Input encryption data is null");
        }
        byte[] encode = new byte[]{};
        for (int i = 0; i < encryptedData.length; i += encodeLen) {
            byte[] subarray = ArrayUtils.subarray(encryptedData, i, i + encodeLen);
            byte[] doFinal = encryptByPublicKey(subarray, key);
            encode = ArrayUtils.addAll(encode, doFinal);
        }
        return encode;
    }

    public static byte[] decryptPrivateKey(byte[] encode, String key) throws Exception {
        if (encode == null) {
            throw new IllegalArgumentException("Input data is null");
        }
        byte[] buffers = new byte[]{};
        for (int i = 0; i < encode.length; i += decodeLen) {
            byte[] subarray = ArrayUtils.subarray(encode, i, i + decodeLen);
            byte[] doFinal = decryptByPrivateKey(subarray, key);
            buffers = ArrayUtils.addAll(buffers, doFinal);
        }
        return buffers;
    }

    public static PublicKey loadPublicKey(String publicKeyStr) throws Exception {
        try {
            byte[] buffer = Base64Utils.decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            //表示根据 ASN.1 类型 SubjectPublicKeyInfo 进行编码的公用密钥的 ASN.1 编码。
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    public static PrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
        try {
            byte[] buffer = Base64Utils.decode(privateKeyStr);
            //表示按照 ASN.1 类型 PrivateKeyInfo 进行编码的专用密钥的 ASN.1 编码。
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    public static PublicKey loadPublicKey(InputStream in) throws Exception {
        try {
            return loadPublicKey(FileUtils.readString(in));
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }

    public static PrivateKey loadPrivateKey(InputStream in) throws Exception {
        try {
            return loadPrivateKey(FileUtils.readString(in));
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        }
    }

    private static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Input data is null");
        }

        Key privateKey = loadPrivateKey(key);
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    private static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Input data is null");
        }

        Key publicKey = loadPublicKey(key);

        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);//publicKey.getAlgorithm()
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    private static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Input data is null");
        }

        Key publicKey = loadPublicKey(key);

        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    private static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Input data is null");
        }

        Key privateKey = loadPrivateKey(key);
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

}

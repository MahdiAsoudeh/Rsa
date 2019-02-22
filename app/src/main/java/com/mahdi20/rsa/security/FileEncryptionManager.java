package com.mahdi20.rsa.security;

import android.util.Log;

import java.io.File;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;


public class FileEncryptionManager {
    private static FileEncryptionManager INSTANCE;

    private String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDXOyXz4E3zIIEKb8SGgL" +
            "6c+Bioe4wXE8ez5VDM91bliaX20bGcaLNtR6RPKHjIOPa/q/n1bEzm/UmSui0RoduAZUh9wUcNH" +
            "z+q0rJ6kzFEAFgHm53NiJkHNJTGrXppEg5tI3ET94nN7jroYHUhtNgzPoy9wGvQQ/vnRAkgTtTZdwIDAQAB";

    String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANc7J" +
            "fPgTfMggQpvxIaAvpz4GKh7jBcTx7PlUMz3VuWJpfbRsZxos21HpE8oeMg49r+r+fVsT" +
            "Ob9SZK6LRGh24BlSH3BRw0fP6rSsnqTMUQAWAebnc2ImQc0lMatemkSDm0jcRP3ic3uOuhgd" +
            "SG02DM+jL3Aa9BD++dECSBO1Nl3AgMBAAECgYBw7/uRRdEBU7wCkvVnsqTSzyh5OCMhdOKklh" +
            "7Y/qydU6Y/pnbxYMtN+3rPgqgmQCXSG9bUnliYGK6DjKfbibgYaCJvK6vDt9Gf1rrA9Js5jD4cO" +
            "ulS2gAfbNKVfqMXa7it5RFR/0W2oKbTi7G7E2qeX8fSimiz+edPqLZ3YHfWiQJBAPCDFTKrffW4J" +
            "avugswoAccwbEe+eIPaWbnbDFYhfPFpaK4hR1/eiazbJMfJi1pml2IqWEp8uFQxyHb8xlNzyasCQ" +
            "QDlF0zdG49frwWVk3iTNyiiSOqMkEiRwPtxfpxeeX2RKd7FGtzajNuOjXZ4XDYJ4m2ISvHQC3A0u" +
            "n+EMMaG49tlAkB6rDFctdG6SeGVD0NRhDpb8ZvZABKSFgXb4RkquUv0CjKlVj4EbQpFy0S4Tlk" +
            "wk9E09aow2+pcr0OzRPyXRiCfAkEAy9wbIxsWT7BAyOTtRBuuhhNa3PC8Ey/m0Q04+v0jlxzqRv3rkH" +
            "QOIOGTjfGIiO08SS9f1aGIHPPk6244C+sR3QJASpr9Yo5jTPwHRCiLxs1xZmF5NxttfAuWK0wHlmrrU" +
            "ouKyx8XAvhPY/DlB/vLbYvY2m9uTsw0Uf6sdKVtFKUzUg==";

    private FileEncryptionManager() {
    }

    public static FileEncryptionManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new FileEncryptionManager();
        }
        return INSTANCE;
    }

    public void setRSAKey(String publicKey, String privateKey, boolean isEncode) throws Exception {
        if (isEncode) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        } else {
            this.publicKey = Base64Utils.encode(publicKey.getBytes());
            this.privateKey = Base64Utils.encode(privateKey.getBytes());
        }
    }

    public void setRSAKey(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws Exception {
        this.publicKey = Base64Utils.encode(publicKey.getEncoded());
        this.privateKey = Base64Utils.encode(privateKey.getEncoded());
    }

    public void generateKey() throws Exception {
        Map<String, Object> map = RSAProvider.generateKeyPair();
        this.privateKey = RSAProvider.getPrivateKeyBytes(map);
        this.publicKey = RSAProvider.getPublicKeyBytes(map);
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public String signByPrivateKey(byte[] data) throws Exception {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("PrivateKey is empty, you should invoke setRSAKey or generateKey");
        }
        return RSAProvider.sign(data, privateKey);
    }

    public boolean verifyByPublicKey(byte[] data, String sign) throws Exception {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        return RSAProvider.verify(data, publicKey, sign);
    }

    public byte[] encryptByPublicKey(byte[] data) throws Exception {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        return RSAProvider.encryptPublicKey(data, publicKey);
    }

    public byte[] decryptByPrivateKey(byte[] data) throws Exception {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("PrivateKey is empty, you should invoke setRSAKey or generateKey");
        }
        return RSAProvider.decryptPrivateKey(data, privateKey);
    }

    public byte[] encryptByPrivateKey(byte[] data) throws Exception {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("PrivateKey is empty, you should invoke setRSAKey or generateKey");
        }
        return RSAProvider.encryptPublicKey(data, privateKey);
    }

    public byte[] decryptByPublicKey(byte[] data) throws Exception {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        return RSAProvider.decryptPrivateKey(data, publicKey);
    }

    public byte[] encryptFileByPublicKey(File inputFile, File outFile) throws Exception {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] data = FileUtils.getDataFromFile(inputFile);
        byte[] encryData = RSAProvider.encryptPublicKey(data, publicKey);
        if (outFile != null) {
            boolean result = FileUtils.saveDataToFile(encryData, outFile);
            Log.d("FileEncryptionManager", "save file result " + result);
        }
        return encryData;
    }

    public byte[] decryptFileByPrivateKey(File inputFile, File outFile) throws Exception {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("PrivateKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] data = FileUtils.getDataFromFile(inputFile);
        byte[] decryData = RSAProvider.decryptPrivateKey(data, privateKey);
        if (outFile != null) {
            boolean result = FileUtils.saveDataToFile(decryData, outFile);
            Log.d("FileEncryptionManager", "save file result " + result);
        }
        return decryData;
    }

    public byte[] encryptFileByPublicKey(byte[] inputData, File outFile) throws Exception {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] encryData = RSAProvider.encryptPublicKey(inputData, publicKey);
        if (outFile != null) {
            boolean result = FileUtils.saveDataToFile(encryData, outFile);
            Log.d("FileEncryptionManager", "save file result " + result);
        }
        return encryData;
    }

    public byte[] decryptFileByPrivateKey(byte[] inputData, File outFile) throws Exception {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("PrivateKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] decryData = RSAProvider.decryptPrivateKey(inputData, privateKey);
        if (outFile != null) {
            boolean result = FileUtils.saveDataToFile(decryData, outFile);
            Log.d("FileEncryptionManager", "save file result " + result);
        }
        return decryData;
    }

    public byte[] encryptFileByPrivateKey(File inputFile, File outFile) throws Exception {
        if (privateKey == null || privateKey.isEmpty()) {
            throw new IllegalArgumentException("PrivateKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] data = FileUtils.getDataFromFile(inputFile);
        byte[] encryData = RSAProvider.encryptPrivateKey(data, privateKey);
        if (outFile != null) {
            boolean result = FileUtils.saveDataToFile(encryData, outFile);
            Log.d("FileEncryptionManager", "save file result " + result);
        }
        return encryData;
    }

    public byte[] decryptFileByPublicKey(File inputFile, File outFile) throws Exception {
        if (publicKey == null || publicKey.isEmpty()) {
            throw new IllegalArgumentException("PublicKey is empty, you should invoke setRSAKey or generateKey");
        }
        byte[] data = FileUtils.getDataFromFile(inputFile);
        byte[] decryData = RSAProvider.decryptPublicKey(data, publicKey);
        if (outFile != null) {
            boolean result = FileUtils.saveDataToFile(decryData, outFile);
            Log.d("FileEncryptionManager", "save file result " + result);
        }
        return decryData;
    }
}

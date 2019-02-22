package com.mahdi20.rsa.security;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;


public class FileUtils {

    public static boolean saveDataToFile(byte[] data, File filePath) {
        if (data == null || filePath == null) {
            throw new IllegalArgumentException("Input data is null or output path is null");
        }
        boolean result = false;
        try {
            result = write(filePath, data, false);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public static byte[] getDataFromFile(File sourceFile) throws FileNotFoundException {
        return getBytesFromInputStream(new FileInputStream(sourceFile));
    }

    public static byte[] getBytesFromInputStream(InputStream inputStream) {
        byte[] buffer = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1000);
        byte[] b = new byte[1000];
        try {
            int n;
            while ((n = inputStream.read(b)) != -1) {
                bos.write(b, 0, n);
            }
            buffer = bos.toByteArray();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                inputStream.close();
                bos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return buffer;
    }

    public static String readString(InputStream in) throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(in));
        String readLine = null;
        StringBuilder sb = new StringBuilder();
        while ((readLine = br.readLine()) != null) {
            if (readLine.charAt(0) == '-') {
                continue;
            } else {
                sb.append(readLine);
                sb.append('\r');
            }
        }

        return sb.toString();
    }

    private static boolean write(File file, byte[] content, boolean append) {
        if (file != null && content != null) {
            if (!file.exists()) {
                file = createNewFile(file);
            }

            FileOutputStream ops = null;

            try {
                ops = new FileOutputStream(file, append);
                ops.write(content);
                return true;
            } catch (Exception var15) {
                var15.printStackTrace();
            } finally {
                try {
                    ops.close();
                } catch (IOException var14) {
                    var14.printStackTrace();
                }
                ops = null;
            }

            return false;
        }
        return false;
    }

    private static File createNewFile(File file) {
        try {
            if (file.exists()) {
                return file;
            } else {
                File e = file.getParentFile();
                if (!e.exists()) {
                    e.mkdirs();
                }

                if (!file.exists()) {
                    file.createNewFile();
                }

                return file;
            }
        } catch (IOException var2) {
            var2.printStackTrace();
            return null;
        }
    }
}

package com.anjia.unidbgserver.utils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class TempFileUtils {

    private static final Map<String, File> TEMP_FILES = new HashMap<>();
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static File getTempFile(String classpathFile) {
        try {
            String md5 = md5Digest(classpathFile);
            if (TEMP_FILES.containsKey(md5)) {
                return TEMP_FILES.get(md5);
            }
            String extension = "";
            int dotIndex = classpathFile.lastIndexOf(".");
            if (dotIndex > 0) {
                extension = classpathFile.substring(dotIndex);
            }
            File tempFile = File.createTempFile("unidbg_", extension);
            tempFile.deleteOnExit();

            InputStream is = TempFileUtils.class.getClassLoader().getResourceAsStream(classpathFile);
            if (is == null) {
                System.err.println("资源文件不存在: " + classpathFile);
                return null;
            }
            try (is; FileOutputStream fos = new FileOutputStream(tempFile)) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = is.read(buf)) != -1) {
                    fos.write(buf, 0, n);
                }
            }
            TEMP_FILES.put(md5, tempFile);
            return tempFile;
        } catch (IOException e) {
            System.err.println("创建临时文件失败: " + classpathFile + " - " + e.getMessage());
            return null;
        }
    }

    public static void cleanup() {
        for (File file : TEMP_FILES.values()) {
            try {
                if (file.exists() && !file.delete()) {
                    file.deleteOnExit();
                }
            } catch (Exception ignored) {}
        }
        TEMP_FILES.clear();
    }

    private static String md5Digest(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return input;
        }
    }
}

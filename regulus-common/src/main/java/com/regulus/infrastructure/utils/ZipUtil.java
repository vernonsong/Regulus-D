package com.regulus.infrastructure.utils;


import java.io.*;
import java.util.Enumeration;
import java.util.Stack;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;


public class ZipUtil {

    private static final int MAX_FILE_NUMBER = 10000; // 最大文件数
    private static final long MAX_EXTRACTED_SIZE = 1024L * 1024 * 1024; // 最大解压大小 1GB

    public static void unpack(File archive, File target) throws IOException {
        // 如果目标目录不存在，直接创建
        if (!target.exists()) {
            if (!target.mkdirs()) {
                throw new IOException("Failed to create target directory");
            }
        }

        int files = 0;
        long totalSize = 0;

        // 检查压缩文件并展开内容
        try (ZipFile zipFile = new ZipFile(archive)) {
            Enumeration<? extends ZipEntry> zipEntries = zipFile.entries();

            while (zipEntries.hasMoreElements()) {
                ZipEntry zipEntry = zipEntries.nextElement();

                File targetFile = new File(target, zipEntry.getName());
                // 确保解压路径在指定解压基础目录内，防止路径穿越攻击
                if (!targetFile.getCanonicalPath().startsWith(target.getCanonicalPath())) {
                    throw new IOException("Potential Path Traversal attack: " + zipEntry.getName());
                }

                if (zipEntry.isDirectory()) {
                    // 创建目录
                    if (!targetFile.exists() && !targetFile.mkdirs()) {
                        throw new IOException("Failed to create directory: " + targetFile);
                    }
                } else {
                    // 解压文件
                    File parentDir = targetFile.getParentFile();
                    if (!parentDir.exists() && !parentDir.mkdirs()) {
                        throw new IOException("Failed to create parent directory: " + parentDir);
                    }

                    try (InputStream inputStream = zipFile.getInputStream(zipEntry);
                         OutputStream outputStream = new FileOutputStream(targetFile)) {

                        byte[] buffer = new byte[8192]; // 增加缓冲大小以优化性能
                        int len;
                        while ((len = inputStream.read(buffer)) > 0) {
                            outputStream.write(buffer, 0, len);
                            totalSize += len;

                            // 检查总解压大小是否超过限制
                            if (totalSize > MAX_EXTRACTED_SIZE) {
                                throw new IOException("Exceeded the maximum extracted size limit, it might be a zip bomb");
                            }
                        }
                    }
                }

                // 检查解压的文件数量是否超过限制
                files++;
                if (files > MAX_FILE_NUMBER) {
                    throw new IOException("Too many files to unzip, it might be a zip bomb");
                }
            }
        } catch (IOException e) {
            // 一旦出错，可通过递归删除已经解压的目标文件
            deleteDirectory(target);
            throw e;
        }
    }

    private static void deleteDirectory(File directory) throws IOException {
        // 参数校验：防止意外情况发生
        if (directory == null || !directory.exists()) {
            return;
        }

        // 借助队列或栈结构避免递归
        Stack<File> stack = new Stack<>();
        stack.push(directory);

        while (!stack.isEmpty()) {
            File current = stack.pop();
            File[] files = current.listFiles();

            if (files != null && files.length > 0) {
                // 如果当前目录仍有子文件，重新压入栈中
                stack.push(current);
                for (File file : files) {
                    if (file.isDirectory()) {
                        stack.push(file);  // 子目录添加到栈中
                    } else {
                        // 删除普通文件
                        if (!file.delete()) {
                            throw new IOException("Failed to delete file: " + file.getAbsolutePath());
                        }
                    }
                }
            } else {
                // 如果目录为空或者无子文件，则删除目录本身
                if (!current.delete()) {
                    throw new IOException("Failed to delete directory: " + current.getAbsolutePath());
                }
            }
        }
    }
}
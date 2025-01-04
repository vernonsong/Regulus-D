package com.regulus.infrastructure.utils;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ZipUtilTest {

    /**
     * Tests for the {@link ZipUtil#unpack(File, File)} method.
     * The method unpacks a zip file into a specified target directory while ensuring security measures.
     */

    @Test
    void testUnpackZipBombTooManyFiles() throws IOException {
        File tempDir = Files.createTempDirectory("unpack-test").toFile();
        tempDir.deleteOnExit();

        File zipFile = new File(tempDir, "zipBomb.zip");
        File targetDir = new File(tempDir, "unpacked");

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
            for (int i = 0; i < 10000 + 1; i++) {
                ZipEntry entry = new ZipEntry("file" + i + ".txt");
                zipOut.putNextEntry(entry);
                zipOut.write("Test".getBytes());
                zipOut.closeEntry();
            }
        }

        IOException exception = assertThrows(IOException.class, () -> ZipUtil.unpack(zipFile, targetDir));
        assertTrue(exception.getMessage().contains("Too many files to unzip"));
        assertFalse(targetDir.exists());
    }

    //
    @Test
    void testUnpackZipBombExceedsMaxSize() throws IOException {
        File tempDir = Files.createTempDirectory("unpack-test").toFile();
        tempDir.deleteOnExit();

        File zipFile = new File(tempDir, "zipBomb.zip");
        File targetDir = new File(tempDir, "unpacked");

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
            ZipEntry entry = new ZipEntry("largeFile.txt");
            zipOut.putNextEntry(entry);
            zipOut.write(new byte[(int) 1024L * 1024 * 1024 + 1]);
            zipOut.closeEntry();
        }

        IOException exception = assertThrows(IOException.class, () -> ZipUtil.unpack(zipFile, targetDir));
        assertTrue(exception.getMessage().contains("Exceeded the maximum extracted size limit"));
        assertFalse(targetDir.exists());

    }

    //
    @Test
    void testUnpackWithPathTraversal() throws IOException {
        File tempDir = Files.createTempDirectory("unpack-test").toFile();
        tempDir.deleteOnExit();

        File zipFile = new File(tempDir, "test.zip");
        File targetDir = new File(tempDir, "unpacked");

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
            ZipEntry entry = new ZipEntry("../maliciousFile.txt");
            zipOut.putNextEntry(entry);
            zipOut.write("This is a malicious file".getBytes());
            zipOut.closeEntry();
        }

        IOException exception = assertThrows(IOException.class, () -> ZipUtil.unpack(zipFile, targetDir));
        assertTrue(exception.getMessage().contains("Potential Path Traversal attack"));
        assertFalse(targetDir.exists());
    }

    @Test
    void testUnpackFailsToCreateTargetDir() {
        File nonWritableDir = new File("/root/unwritable");
        File zipFile = new File(nonWritableDir, "test.zip");

        IOException exception = assertThrows(IOException.class, () -> ZipUtil.unpack(zipFile, nonWritableDir));
        assertTrue(exception.getMessage().contains("Failed to create target directory"));
    }

    @Test
    void testUnpackZipWithMultipleLevels() throws IOException {
        File tempDir = Files.createTempDirectory("unpack-test").toFile();
        tempDir.deleteOnExit();

        File zipFile = new File(tempDir, "multiLevel.zip");
        File targetDir = new File(tempDir, "unpacked");

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
            // 创建多层目录结构
            zipOut.putNextEntry(new ZipEntry("level1/"));
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("level1/level2/"));
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("level1/level2/file.txt"));
            zipOut.write("This is a file in nested directories.".getBytes());
            zipOut.closeEntry();
        }

        // 执行解压缩，验证解压是否正确
        ZipUtil.unpack(zipFile, targetDir);
        File nestedFile = new File(targetDir, "level1/level2/file.txt");

        assertTrue(nestedFile.exists(), "解压后的文件应存在: level1/level2/file.txt");
        assertEquals("This is a file in nested directories.",
                Files.readString(nestedFile.toPath()),
                "解压后的文件内容不正确");
    }

    @Test
    void testUnpackZipWithMultipleFiles() throws IOException {
        File tempDir = Files.createTempDirectory("unpack-test").toFile();
        tempDir.deleteOnExit();

        File zipFile = new File(tempDir, "multiFile.zip");
        File targetDir = new File(tempDir, "unpacked");

        try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
            // 创建多个文件
            zipOut.putNextEntry(new ZipEntry("file1.txt"));
            zipOut.write("Content of file1.".getBytes());
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("file2.txt"));
            zipOut.write("Content of file2.".getBytes());
            zipOut.closeEntry();

            zipOut.putNextEntry(new ZipEntry("file3.txt"));
            zipOut.write("Content of file3.".getBytes());
            zipOut.closeEntry();
        }

        // 执行解压缩，验证解压是否正确
        ZipUtil.unpack(zipFile, targetDir);

        // 验证文件 1
        File file1 = new File(targetDir, "file1.txt");
        assertTrue(file1.exists(), "解压后的文件应存在: file1.txt");
        assertEquals("Content of file1.", Files.readString(file1.toPath()), "文件1内容不正确");

        // 验证文件 2
        File file2 = new File(targetDir, "file2.txt");
        assertTrue(file2.exists(), "解压后的文件应存在: file2.txt");
        assertEquals("Content of file2.", Files.readString(file2.toPath()), "文件2内容不正确");

        // 验证文件 3
        File file3 = new File(targetDir, "file3.txt");
        assertTrue(file3.exists(), "解压后的文件应存在: file3.txt");
        assertEquals("Content of file3.", Files.readString(file3.toPath()), "文件3内容不正确");
    }
}
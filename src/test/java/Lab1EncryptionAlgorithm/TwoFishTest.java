package Lab1EncryptionAlgorithm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static Utils.CommonUtils.convertByteArrayToLongArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class TwoFishTest {
    @Test
    @DisplayName("Шифровка и расшифровка блоков при ключе из 128 бит")
    void encryptOneBlockKey128BitsTest() {
        TwoFish twoFish = new TwoFish(new long[]{0, 0});
        byte[] plainText = new byte[16];
        byte[] cipherText = twoFish.encryptOneBlock(plainText);
        assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
        for (int i = 0; i < 48; i++) {
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish.encryptOneBlock(plainText);
            assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
            twoFish = new TwoFish(convertByteArrayToLongArray(plainText));
        }
        byte[] expectedResult = new byte[]{0x5D, (byte) 0x9D, 0x4E, (byte) 0xEF, (byte) 0xFA, (byte) 0x91, 0x51, 0x57,
                0x55, 0x24, (byte) 0xF1, 0x15, (byte) 0x81, 0x5A, 0x12, (byte) 0xE0};
        assertArrayEquals(cipherText, expectedResult);
    }

    @Test
    @DisplayName("Шифровка и расшифровка блоков при ключе из 192 бит")
    void encryptOneBlockKey192BitsTest() {
        TwoFish twoFish = new TwoFish(new long[]{0, 0, 0});
        byte[] plainText = new byte[16];
        byte[] cipherText = twoFish.encryptOneBlock(plainText);
        byte[] greatestBytesOfPlainText = new byte[8];
        assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
        for (int i = 0; i < 48; i++) {
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish.encryptOneBlock(plainText);
            assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
            byte[] keyBytes = new byte[24];
            System.arraycopy(plainText, 0, keyBytes, 0, plainText.length);
            System.arraycopy(greatestBytesOfPlainText, 0, keyBytes, 16, 8);
            System.arraycopy(plainText, 0, greatestBytesOfPlainText, 0, 8);
            twoFish = new TwoFish(convertByteArrayToLongArray(keyBytes));
        }
        byte[] expectedResult = new byte[]{(byte) 0xE7, 0x54, 0x49, 0x21, 0x2B, (byte) 0xEE, (byte) 0xF9, (byte) 0xF4,
                (byte) 0xA3, (byte) 0x90, (byte) 0xBD, (byte) 0x86, 0x0A, 0x64, 0x09, 0x41};
        assertArrayEquals(cipherText, expectedResult);
    }

    @Test
    @DisplayName("Шифровка и расшифровка блоков при ключе из 256 бит")
    void encryptOneBlockKey256BitsTest() {
        TwoFish twoFish = new TwoFish(new long[]{0, 0, 0, 0});
        byte[] plainText = new byte[16];
        byte[] cipherText = twoFish.encryptOneBlock(plainText);
        byte[] copyOfPlainText = new byte[16];
        assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
        for (int i = 0; i < 48; i++) {
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish.encryptOneBlock(plainText);
            assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
            byte[] keyBytes = new byte[32];
            System.arraycopy(plainText, 0, keyBytes, 0, plainText.length);
            System.arraycopy(copyOfPlainText, 0, keyBytes, 16, 16);
            System.arraycopy(plainText, 0, copyOfPlainText, 0, 16);
            twoFish = new TwoFish(convertByteArrayToLongArray(keyBytes));
        }
        byte[] expectedResult = new byte[]{0x37, (byte) 0xFE, 0x26, (byte) 0xFF, 0x1C, (byte) 0xF6, 0x61, 0x75,
                (byte) 0xF5, (byte) 0xDD, (byte) 0xF4, (byte) 0xC3, 0x3B, (byte) 0x97, (byte) 0xA2, 0x05};
        assertArrayEquals(cipherText, expectedResult);
    }
}

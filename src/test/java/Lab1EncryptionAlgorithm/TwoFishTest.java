package Lab1EncryptionAlgorithm;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static Lab1EncryptionAlgorithm.TwoFishUtils.convertCharArrayToLongArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class TwoFishTest {
    @Test
    @DisplayName("Шифровка и расшифровка блоков при ключе из 128 бит")
    void encryptOneBlockKey128BitsTest() {
        TwoFish twoFish = new TwoFish(new long[]{0, 0});
        char[] plainText = new char[16];
        char[] cipherText = twoFish.encryptOneBlock(plainText);
        assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
        for (int i = 0; i < 48; i++) {
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish.encryptOneBlock(plainText);
            assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
            twoFish = new TwoFish(convertCharArrayToLongArray(plainText));
        }
        assertArrayEquals(cipherText, new char[]{0x5D, 0x9D, 0x4E, 0xEF, 0xFA, 0x91, 0x51, 0x57, 0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0});
    }

    @Test
    @DisplayName("Шифровка и расшифровка блоков при ключе из 192 бит")
    void encryptOneBlockKey192BitsTest() {
        TwoFish twoFish = new TwoFish(new long[]{0, 0, 0});
        char[] plainText = new char[16];
        char[] cipherText = twoFish.encryptOneBlock(plainText);
        char[] greatestBytesOfPlainText = new char[8];
        assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
        for (int i = 0; i < 48; i++) {
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish.encryptOneBlock(plainText);
            assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
            char[] keyBytes = new char[24];
            System.arraycopy(plainText, 0, keyBytes, 0, plainText.length);
            System.arraycopy(greatestBytesOfPlainText, 0, keyBytes, 16, 8);
            System.arraycopy(plainText, 0, greatestBytesOfPlainText, 0, 8);
            twoFish = new TwoFish(convertCharArrayToLongArray(keyBytes));
        }

        assertArrayEquals(cipherText, new char[]{0xE7, 0x54, 0x49, 0x21, 0x2B, 0xEE, 0xF9, 0xF4, 0xA3, 0x90, 0xBD, 0x86, 0x0A, 0x64, 0x09, 0x41});
    }

    @Test
    @DisplayName("Шифровка и расшифровка блоков при ключе из 256 бит")
    void encryptOneBlockKey256BitsTest() {
        TwoFish twoFish = new TwoFish(new long[]{0, 0, 0, 0});
        char[] plainText = new char[16];
        char[] cipherText = twoFish.encryptOneBlock(plainText);
        char[] copyOfPlainText = new char[16];
        assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
        for (int i = 0; i < 48; i++) {
            System.arraycopy(cipherText, 0, plainText, 0, cipherText.length);
            cipherText = twoFish.encryptOneBlock(plainText);
            assertArrayEquals(twoFish.decryptOneBlock(cipherText), plainText);
            char[] keyBytes = new char[32];
            System.arraycopy(plainText, 0, keyBytes, 0, plainText.length);
            System.arraycopy(copyOfPlainText, 0, keyBytes, 16, 16);
            System.arraycopy(plainText, 0, copyOfPlainText, 0, 16);
            twoFish = new TwoFish(convertCharArrayToLongArray(keyBytes));
        }
        assertArrayEquals(cipherText, new char[]{0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75, 0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05});
    }
}

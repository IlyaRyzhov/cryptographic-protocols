package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.TwoFish;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class EncryptionModesTest {
    GOST34122015 gost34122015 = new GOST34122015(new byte[]{(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
            0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef});
    byte[] message = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99,
            (byte) 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff,
            0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
            (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
            (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11};
    byte[] initializationVector = new byte[]{0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xab, (byte) 0xce, (byte) 0xf0, (byte) 0xa1, (byte) 0xb2,
            (byte) 0xc3, (byte) 0xd4, (byte) 0xe5, (byte) 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
            (byte) 0x89, (byte) 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};

    @Test
    @DisplayName("Шифрование и расшифровка сообщений в режиме CBC")
    void encryptMessageEncryptionAlgorithmWithCBCTest() {
        EncryptionAlgorithmWithCBC encryptionAlgorithmWithCBC = new EncryptionAlgorithmWithCBC(gost34122015, 2);
        encryptionAlgorithmWithCBC.setInitializationVector(initializationVector);
        byte[] cipherMessage = encryptionAlgorithmWithCBC.encryptMessage(message);
        byte[] expected = convertLongArrayToByteArray(new long[]{0x689972d4a085fa4dL, 0x90e52e3d6d7dcc27L, 0x2826e661b478eca6L,
                0xaf1e8e448d5ea5acL, 0xfe7babf1e91999e8L, 0x5640e8b0f49d90d0L, 0x167688065a895c63L, 0x1a2d9a1560b63970L});
        assertArrayEquals(Arrays.copyOf(cipherMessage, expected.length), expected);
        assertArrayEquals(encryptionAlgorithmWithCBC.decryptMessage(cipherMessage), message);
        encryptFileTest(new EncryptionAlgorithmWithCBC(new TwoFish(new long[2]), 2));
    }

    @Test
    @DisplayName("Шифрование и расшифровка сообщений в режиме ECB")
    void encryptMessageEncryptionAlgorithmWithECBTest() {
        EncryptionAlgorithmWithECB encryptionAlgorithmWithECB = new EncryptionAlgorithmWithECB(gost34122015);
        byte[] cipherMessage = encryptionAlgorithmWithECB.encryptMessage(message);
        byte[] expected = convertLongArrayToByteArray(new long[]{0x7f679d90bebc2430L, 0x5a468d42b9d4edcdL, 0xb429912c6e0032f9L,
                0x285452d76718d08bL, 0xf0ca33549d247ceeL, 0xf3f5a5313bd4b157L, 0xd0b09ccde830b9ebL, 0x3a02c4c5aa8ada98L});
        assertArrayEquals(Arrays.copyOf(cipherMessage, expected.length), expected);
        assertArrayEquals(encryptionAlgorithmWithECB.decryptMessage(cipherMessage), message);
    }

    @Test
    @DisplayName("Шифрование и расшифровка сообщений в режиме OFB")
    void encryptMessageEncryptionAlgorithmWithOFBTest() {
        EncryptionAlgorithmWithOFB encryptionAlgorithmWithOFB = new EncryptionAlgorithmWithOFB(gost34122015, 2, 16);
        encryptionAlgorithmWithOFB.setInitializationVector(initializationVector);
        byte[] cipherMessage = encryptionAlgorithmWithOFB.encryptMessage(message);
        byte[] expected = convertLongArrayToByteArray(new long[]{0x81800a59b1842b24L, 0xff1f795e897abd95L, 0xed5b47a7048cfab4L, 0x8fb521369d9326bfL,
                0x66a257ac3ca0b8b1L, 0xc80fe7fc10288a13L, 0x203ebbc066138660L, 0xa0292243f6903150L});
        assertArrayEquals(Arrays.copyOf(cipherMessage, expected.length), expected);
        assertArrayEquals(encryptionAlgorithmWithOFB.decryptMessage(cipherMessage), message);
    }

    @Test
    @DisplayName("Шифрование и расшифровка сообщений в режиме MGM")
    void encryptMessageEncryptionAlgorithmWithMGMTest() {
        byte[] message = new byte[]{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x04, 0x04, 0x04, 0x04,
                0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, (byte) 0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x11, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88, 0x00, 0x11,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x11, 0x22,
                0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x22, 0x33,
                0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11, (byte) 0xaa,
                (byte) 0xbb, (byte) 0xcc};
        EncryptionAlgorithmWithMGM encryptionAlgorithmWithMGM = new EncryptionAlgorithmWithMGM(gost34122015, 16, 41);
        byte[] initializationVector = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xFF, (byte) 0xee, (byte) 0xDD, (byte) 0xcc, (byte) 0xbb,
                (byte) 0xaa, (byte) 0x99, (byte) 0x88};
        encryptionAlgorithmWithMGM.setInitializationVector(initializationVector);
        byte[] cipherMessage = encryptionAlgorithmWithMGM.encryptMessage(message);
        byte[] expectedAdditionalAuthenticatedData = new byte[]{0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04,
                0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, (byte) 0xea, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05};
        assertArrayEquals(expectedAdditionalAuthenticatedData, Arrays.copyOf(cipherMessage, expectedAdditionalAuthenticatedData.length));
        byte[] expectedCipherData = new byte[]{(byte) 0xa9, 0x75, 0x7b, (byte) 0x81, 0x47, (byte) 0x95, 0x6e, (byte) 0x90, 0x55, (byte) 0xb8, (byte) 0xa3, 0x3D, (byte) 0xe8,
                (byte) 0x9F, 0x42, (byte) 0xFC, (byte) 0x80, 0x75, (byte) 0xD2, 0x21, 0x2b, (byte) 0xF9, (byte) 0xFD, 0x5b, (byte) 0xD3, (byte) 0xF7, 0x06, (byte) 0x9A, (byte) 0xAD,
                (byte) 0xc1, 0x6b, 0x39, 0x49, 0x7a, (byte) 0xb1, 0x59, 0x15, (byte) 0xa6, (byte) 0xba, (byte) 0x85, (byte) 0x93, 0x6b, 0x5D, 0x0e, (byte) 0xa9, (byte) 0xF6, (byte) 0x85,
                0x1c, (byte) 0xc6, 0x0c, 0x14, (byte) 0xD4, (byte) 0xD3, (byte) 0xF8, (byte) 0x83, (byte) 0xD0, (byte) 0xab, (byte) 0x94, 0x42, 0x06, (byte) 0x95, (byte) 0xc7, 0x6D,
                (byte) 0xeb, 0x2c, 0x75, 0x52};
        byte[] cipherData = Arrays.copyOfRange(cipherMessage, expectedAdditionalAuthenticatedData.length, expectedAdditionalAuthenticatedData.length + expectedCipherData.length);
        assertArrayEquals(cipherData, expectedCipherData);
        byte[] expectedImitationInsert = new byte[]{(byte) 0xCF, 0x5D, 0x65, 0x6F, 0x40, (byte) 0xc3, 0x4F, 0x5c, 0x46, (byte) 0xe8, (byte) 0xbb, 0x0e, 0x29, (byte) 0xFC, (byte) 0xDB, 0x4c};
        byte[] imitationInsert = Arrays.copyOfRange(cipherMessage, cipherMessage.length - encryptionAlgorithmWithMGM.getInitializationVector().length, cipherMessage.length);
        assertArrayEquals(imitationInsert, expectedImitationInsert);
        byte[] plainMessage = encryptionAlgorithmWithMGM.decryptMessage(cipherMessage);
        assertArrayEquals(plainMessage, message);

    }

    @Test
    @DisplayName("Шифрование и расшифровка сообщений в режиме CTR-ACPKM")
    void encryptMessageEncryptionAlgorithmWithCTRACPKMTest() {
        EncryptionAlgorithmWithCTRACPKM encryptionAlgorithmWithCTRACPKM = new EncryptionAlgorithmWithCTRACPKM(gost34122015, 2, 16);
        byte[] message = new byte[]{
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a,
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00,
                0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11,
                0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xEE, (byte) 0xFF, 0x0A, 0x00, 0x11, 0x22,
                0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xEE, (byte) 0xFF, 0x0A, 0x00, 0x11, 0x22, 0x33,
                0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA, (byte) 0xBB, (byte) 0xCC, (byte) 0xEE, (byte) 0xFF, 0x0A, 0x00, 0x11, 0x22, 0x33, 0x44};
        byte[] initializationVector = new byte[]{0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xab, (byte) 0xce, (byte) 0xf0};
        encryptionAlgorithmWithCTRACPKM.setInitializationVector(initializationVector);
        byte[] cipherMessage = encryptionAlgorithmWithCTRACPKM.encryptMessage(message);
        byte[] expected = new byte[]{(byte) 0xF1, (byte) 0x95, (byte) 0xD8, (byte) 0xBE, (byte) 0xC1, 0x0e, (byte) 0xD1, (byte) 0xDB, (byte) 0xD5, 0x7b, 0x5F, (byte) 0xa2,
                0x40, (byte) 0xBD, (byte) 0xA1, (byte) 0xb8, (byte) 0x85, (byte) 0xee, (byte) 0xe7, 0x33, (byte) 0xF6, (byte) 0xa1, 0x3e, 0x5D, (byte) 0xF3, 0x3c, (byte) 0xe4,
                (byte) 0xb3, 0x3c, 0x45, (byte) 0xDe, (byte) 0xe4, 0x4b, (byte) 0xce, (byte) 0xeb, (byte) 0x8F, 0x64, 0x6F, 0x4c, 0x55, 0x00, 0x17, 0x06, 0x27, 0x5e, (byte) 0x85,
                (byte) 0xe8, 0x00, 0x58, 0x7c, 0x4D, (byte) 0xF5, 0x68, (byte) 0xD0, (byte) 0x94, 0x39, 0x3e, 0x48, 0x34, (byte) 0xAF, (byte) 0xD0, (byte) 0x80, 0x50, 0x46,
                (byte) 0xCF, 0x30, (byte) 0xF5, 0x76, (byte) 0x86, (byte) 0xae, (byte) 0xec, (byte) 0xE1, 0x1C, (byte) 0xFC, 0x6c, 0x31, 0x6b, (byte) 0x8a, (byte) 0x89, 0x6e,
                (byte) 0xDF, (byte) 0xFD, 0x07, (byte) 0xec, (byte) 0x81, 0x36, 0x36, 0x46, 0x0c, 0x4F, 0x3b, 0x74, 0x34, 0x23, 0x16, 0x3e, 0x64, 0x09, (byte) 0xa9, (byte) 0xc2,
                (byte) 0x82, (byte) 0xFA, (byte) 0xc8, (byte) 0xD4, 0x69, (byte) 0xD2, 0x21, (byte) 0xe7, (byte) 0xFB, (byte) 0xD6, (byte) 0xDE, 0x5D};
        assertArrayEquals(cipherMessage, expected);
    }

    @Test
    @DisplayName("Получение имитовставки в режиме OMAC")
    void getImitationInsertEncryptionAlgorithmWithOMACTest() {
        EncryptionAlgorithmWithOMAC encryptionAlgorithmWithOMAC = new EncryptionAlgorithmWithOMAC(gost34122015, 8);
        assertArrayEquals(encryptionAlgorithmWithOMAC.getImitationInsertFromMessage(message), convertLongArrayToByteArray(new long[]{0x336f4d296059fbe3L}));
        encryptionAlgorithmWithOMAC = new EncryptionAlgorithmWithOMAC(new TwoFish(new long[2]), 8);
        File file = new File("C:\\Users\\fvd\\Desktop\\10MB.txt");
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file))) {
            byte[] plainData = bufferedInputStream.readAllBytes();
            byte[] expectedImitationInsert = encryptionAlgorithmWithOMAC.getImitationInsertFromMessage(plainData);
            byte[] realImitationInsert = encryptionAlgorithmWithOMAC.getImitationInsertFromFile(file);
            assertArrayEquals(expectedImitationInsert, realImitationInsert);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //todo протвестить мгм
    @Test
    @DisplayName("Шифрование файлов в режимах CBC, CTR-ACPKM, ECB, MGM, OFB")
    void encryptFileEncryptionAlgorithmWithModeTest() {
        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithECB encryptionAlgorithmWithECB = new EncryptionAlgorithmWithECB(twoFish);
        encryptFileTest(encryptionAlgorithmWithECB);
        decryptFileTest(encryptionAlgorithmWithECB);
        EncryptionAlgorithmWithCBC encryptionAlgorithmWithCBC = new EncryptionAlgorithmWithCBC(twoFish, 2);
        encryptFileTest(encryptionAlgorithmWithCBC);
        decryptFileTest(encryptionAlgorithmWithCBC);
        EncryptionAlgorithmWithOFB encryptionAlgorithmWithOFB = new EncryptionAlgorithmWithOFB(twoFish, 2, 16);
        encryptFileTest(encryptionAlgorithmWithOFB);
        decryptFileTest(encryptionAlgorithmWithOFB);
        EncryptionAlgorithmWithCTRACPKM encryptionAlgorithmWithCTRACPKM = new EncryptionAlgorithmWithCTRACPKM(twoFish, 2, 16);
        encryptFileTest(encryptionAlgorithmWithCTRACPKM);
        decryptFileTest(encryptionAlgorithmWithCTRACPKM);
    }

    private void encryptFileTest(EncryptionAlgorithmAbstract encryptionAlgorithmAbstract) {
        File file = new File("C:\\Users\\fvd\\Desktop\\10MB.txt");
        File encryptedFile = new File("C:\\Users\\fvd\\Desktop\\10MB.txt.encrypted");
        String pathForEncryptedFile = "C:\\Users\\fvd\\Desktop";
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
             BufferedInputStream bufferedInputStreamEncrypted = new BufferedInputStream(new FileInputStream(encryptedFile))) {
            byte[] plainData = bufferedInputStream.readAllBytes();
            byte[] encryptedDataExpected = encryptionAlgorithmAbstract.encryptMessage(plainData);
            encryptionAlgorithmAbstract.encryptFile(file, pathForEncryptedFile);
            byte[] realEncryptedData = bufferedInputStreamEncrypted.readAllBytes();
            assertArrayEquals(encryptedDataExpected, realEncryptedData, "" + encryptionAlgorithmAbstract);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void decryptFileTest(EncryptionAlgorithmAbstract encryptionAlgorithmAbstract) {
        File plainFile = new File("C:\\Users\\fvd\\Desktop\\10MB.txt");
        File encryptedFile = new File("C:\\Users\\fvd\\Desktop\\10MB.txt.encrypted");
        File decryptedFile = new File("C:\\Users\\fvd\\Desktop\\decrypted_10MB.txt");
        String pathForDecryptedFile = "C:\\Users\\fvd\\Desktop";
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(plainFile));
             BufferedInputStream bufferedInputStreamDecrypted = new BufferedInputStream(new FileInputStream(decryptedFile))) {
            byte[] expectedPlainData = bufferedInputStream.readAllBytes();
            encryptionAlgorithmAbstract.decryptFile(encryptedFile, pathForDecryptedFile);
            byte[] realPlainData = bufferedInputStreamDecrypted.readAllBytes();
            assertArrayEquals(realPlainData, expectedPlainData);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
        EncryptionAlgorithmWithECB encryptionAlgorithmWithCBC = new EncryptionAlgorithmWithECB(new TwoFish(new long[2]));
        encryptionAlgorithmWithCBC.encryptFile(new File("C:\\Users\\fvd\\Desktop\\10MB.txt"), "C:\\Users\\fvd\\Desktop");
    }
}

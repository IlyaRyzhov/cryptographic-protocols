package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.createAbsoluteDecryptedFileName;
import static Utils.CommonUtils.createAbsoluteEncryptedFileName;
import static Utils.EncryptionModesUtils.generateInitializationVector;
import static Utils.EncryptionModesUtils.shiftLeftRegisterWithFillingLSB;

class EncryptionAlgorithmWithCBC extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    public EncryptionAlgorithmWithCBC(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * blockSizeInBytes];
        generateInitializationVector(initializationVector);
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int numberOfBlocksInEncryptedMessage = (plainText.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        int remainderBytes = plainText.length % blockSizeInBytes;
        byte[] paddingBlock = new byte[blockSizeInBytes];
        if (remainderBytes == 0) {
            paddingBlock[0] = 1;
        } else {
            System.arraycopy(plainText, (numberOfBlocksInEncryptedMessage - 1) * blockSizeInBytes, paddingBlock, 0, remainderBytes);
            paddingBlock[remainderBytes] = 1;
        }
        for (int i = 0; i < numberOfBlocksInEncryptedMessage; i++) {
            for (int j = 0; j < blockSizeInBytes; j++) {
                if (i != numberOfBlocksInEncryptedMessage - 1)
                    currentInitializationVector[j] ^= plainText[j + i * blockSizeInBytes];
                else currentInitializationVector[j] ^= paddingBlock[j];
            }
            encryptOneBlockOfMessage(currentInitializationVector, blockSizeInBytes, encryptedMessage, i);
        }
        return encryptedMessage;
    }

    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), 1048576)) {
            while (bufferedInputStream.available() > 0) {
                byte[] plainData = new byte[Math.min(1048576, bufferedInputStream.available())];
                bufferedInputStream.read(plainData, 0, plainData.length);
                int numberOfBlocksToEncrypt = plainData.length / blockSizeInBytes;
                int remainderBytes = plainData.length % blockSizeInBytes;
                byte[] cipherData = new byte[numberOfBlocksToEncrypt * blockSizeInBytes];
                for (int i = 0; i < numberOfBlocksToEncrypt; i++) {
                    for (int j = 0; j < blockSizeInBytes; j++) {
                        currentInitializationVector[j] ^= plainData[j + i * blockSizeInBytes];
                    }
                    encryptOneBlockOfMessage(currentInitializationVector, blockSizeInBytes, cipherData, i);
                }
                bufferedOutputStream.write(cipherData);
                if (bufferedInputStream.available() == 0) {
                    byte[] paddingBlock = new byte[blockSizeInBytes];
                    if (remainderBytes == 0) {
                        paddingBlock[0] = 1;
                    } else {
                        System.arraycopy(plainData, numberOfBlocksToEncrypt * blockSizeInBytes, paddingBlock, 0, remainderBytes);
                        paddingBlock[remainderBytes] = 1;
                    }
                    for (int j = 0; j < blockSizeInBytes; j++) {
                        currentInitializationVector[j] ^= paddingBlock[j];
                    }
                    encryptOneBlockOfMessage(currentInitializationVector, blockSizeInBytes, paddingBlock, 0);
                    bufferedOutputStream.write(paddingBlock);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int numberOfBlocks = cipherText.length / blockSizeInBytes;
        byte[] decryptedMessage = new byte[cipherText.length];
        decryptSequenceOfBlocksInMessage(currentInitializationVector, blockSizeInBytes, cipherText, numberOfBlocks, decryptedMessage);
        return removePadding(decryptedMessage);
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), 1048576)) {
            while (bufferedInputStream.available() > 0) {
                byte[] cipherData = new byte[Math.min(1048576, bufferedInputStream.available())];
                bufferedInputStream.read(cipherData, 0, cipherData.length);
                int numberOfBlocksToDecrypt = cipherData.length / blockSizeInBytes;
                byte[] plainData = new byte[numberOfBlocksToDecrypt * blockSizeInBytes];
                decryptSequenceOfBlocksInMessage(currentInitializationVector, blockSizeInBytes, cipherData, numberOfBlocksToDecrypt, plainData);
                if (bufferedInputStream.available() > 0)
                    bufferedOutputStream.write(plainData);
                else {
                    bufferedOutputStream.write(removePadding(plainData));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //TODO Подумать, мб убрать выделенные методы с кучей параметров и вынести параметры типа blockSizeInBytes в поля класса
    private void decryptSequenceOfBlocksInMessage(byte[] currentInitializationVector, int blockSizeInBytes, byte[] cipherData, int numberOfBlocksToDecrypt, byte[] plainData) {
        for (int i = 0; i < numberOfBlocksToDecrypt; i++) {
            byte[] decryptedBlock = encryptionAlgorithm.decryptOneBlock(Arrays.copyOfRange(cipherData, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            for (int j = 0; j < blockSizeInBytes; j++) {
                decryptedBlock[j] ^= currentInitializationVector[j];
            }
            byte[] encryptedBlock = Arrays.copyOfRange(cipherData, i * blockSizeInBytes, (i + 1) * blockSizeInBytes);
            shiftLeftRegisterWithFillingLSB(currentInitializationVector, encryptedBlock);
            System.arraycopy(decryptedBlock, 0, plainData, i * blockSizeInBytes, blockSizeInBytes);
        }
    }

    private void encryptOneBlockOfMessage(byte[] currentInitializationVector, int blockSizeInBytes, byte[] cipherData, int offsetBlocksInCipherData) {
        byte[] encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
        shiftLeftRegisterWithFillingLSB(currentInitializationVector, encryptedBlock);
        System.arraycopy(encryptedBlock, 0, cipherData, offsetBlocksInCipherData * blockSizeInBytes, blockSizeInBytes);
    }

    @Override
    public byte[] getInitializationVector() {
        return initializationVector;
    }

    @Override
    public void setInitializationVector(byte[] initializationVector) {
        this.initializationVector = initializationVector;
    }

    public static void main(String[] args) {
/*        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithCipherBlockChaining encryptionAlgorithmWithCipherBlockChaining = new EncryptionAlgorithmWithCipherBlockChaining(twoFish, 3);
        encryptionAlgorithmWithCipherBlockChaining.encryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"), "C:\\Users\\fvd\\Desktop");
        encryptionAlgorithmWithCipherBlockChaining.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");*/
 /*       byte[] iv = new byte[]{0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xab, (byte) 0xce, (byte) 0xf0, (byte) 0xa1, (byte) 0xb2,
                (byte) 0xc3, (byte) 0xd4, (byte) 0xe5, (byte) 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
                (byte) 0x89, (byte) 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
        GOST34122015 gost34122015 = new GOST34122015(new byte[]{(byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff,
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef});
        byte[] pt1 = new byte[]{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99,
                (byte) 0x88, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff,
                0x0a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99,
                (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xee, (byte) 0xff, 0x0a, 0x00, 0x11};
        EncryptionAlgorithmWithCBC encryptionAlgorithmWithCBC1 = new EncryptionAlgorithmWithCBC(gost34122015, 2);
        encryptionAlgorithmWithCBC1.setInitializationVector(iv);
        byte[] ct= encryptionAlgorithmWithCBC1.encryptMessage(pt1);
        for (int i = 0; i < ct.length; i++) {
            System.out.print(Integer.toHexString(ct[i] & 0xff));
        }*/
    }

}

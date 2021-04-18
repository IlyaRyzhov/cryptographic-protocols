package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.createAbsoluteDecryptedFileName;
import static Utils.CommonUtils.createAbsoluteEncryptedFileName;

class EncryptionAlgorithmWithCipherBlockChaining extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    public EncryptionAlgorithmWithCipherBlockChaining(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocksInEncryptedMessage = (plainText.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        int remainderBytes = plainText.length % encryptionAlgorithm.getBlockSizeInBytes();
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
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
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
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = cipherText.length / blockSizeInBytes;
        byte[] decryptedMessage = new byte[cipherText.length];
        decryptSequenceOfBlocksInMessage(currentInitializationVector, blockSizeInBytes, cipherText, numberOfBlocks, decryptedMessage);
        return removePadding(decryptedMessage);
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
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
        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithCipherBlockChaining encryptionAlgorithmWithCipherBlockChaining = new EncryptionAlgorithmWithCipherBlockChaining(twoFish, 3);
        encryptionAlgorithmWithCipherBlockChaining.encryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt"), "C:\\Users\\fvd\\Desktop");
        encryptionAlgorithmWithCipherBlockChaining.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");
/*        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0xff);
        byte[] pt = new byte[16];
        Arrays.fill(pt, (byte) 0xff);
        encryptionAlgorithmWithCipherBlockChaining.setInitializationVector(iv);
        byte[] ct = encryptionAlgorithmWithCipherBlockChaining.encryptMessage(pt);
        System.out.println(Arrays.toString(ct));
        System.out.println(Arrays.toString(encryptionAlgorithmWithCipherBlockChaining.decryptMessage(ct)));
        //16 [-97, 88, -97, 92, -10, 18, 44, 50, -74, -65, -20, 47, 42, -24, -61, 90, -79, 64, -13, 66, 50, -23, -1, 87, -100, 24, 92, 11, 22, -103, -102, -77]
        //10 [53, -74, 12, -121, 15, -26, 37, -120, 40, -3, 9, 112, -91, 17, 40, 38]*/
    }

}

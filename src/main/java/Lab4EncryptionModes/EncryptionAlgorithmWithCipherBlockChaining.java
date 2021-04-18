package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.createAbsoluteEncryptedFileName;

class EncryptionAlgorithmWithCipherBlockChaining extends EncryptionAlgorithmAbstract implements EncryptionModeWithInitializationVector {
    private byte[] initializationVector;

    public EncryptionAlgorithmWithCipherBlockChaining(EncryptionAlgorithm encryptionAlgorithm, int numberOfBlocksInShiftRegister) {
        super(encryptionAlgorithm);
        initializationVector = new byte[numberOfBlocksInShiftRegister * encryptionAlgorithm.getBlockSizeInBytes()];
        generateInitializationVector(initializationVector);
    }

    public EncryptionAlgorithmWithCipherBlockChaining(EncryptionAlgorithm encryptionAlgorithm, byte[] initializationVector) {
        super(encryptionAlgorithm);
        setInitializationVector(initializationVector);
    }

    //TODO Продебажить
    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocksInEncryptedMessage = (plainText.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        int remainderBytes = plainText.length % encryptionAlgorithm.getBlockSizeInBytes();
        byte[] paddingBlock = new byte[16];
        if (remainderBytes == 0) {
            paddingBlock[0] = 1;
        } else {
            System.arraycopy(plainText, (numberOfBlocksInEncryptedMessage - 1) * 16, paddingBlock, 0, remainderBytes);
            paddingBlock[remainderBytes] = 1;
        }
        for (int i = 0; i < numberOfBlocksInEncryptedMessage; i++) {
            for (int j = 0; j < blockSizeInBytes; j++) {
                if (i != numberOfBlocksInEncryptedMessage - 1)
                    currentInitializationVector[j] ^= plainText[j + i * blockSizeInBytes];
                else currentInitializationVector[j] ^= paddingBlock[j];
            }
            byte[] encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOf(currentInitializationVector, blockSizeInBytes));
            byte[] rightPartOfCurrentInitializationVector = Arrays.copyOfRange(currentInitializationVector, blockSizeInBytes, initializationVector.length);
            System.arraycopy(rightPartOfCurrentInitializationVector, 0, currentInitializationVector, 0, rightPartOfCurrentInitializationVector.length);
            System.arraycopy(encryptedBlock, 0, currentInitializationVector, rightPartOfCurrentInitializationVector.length, encryptedBlock.length);
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return encryptedMessage;
    }


    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        byte[] currentInitializationVector = new byte[initializationVector.length];
        System.arraycopy(initializationVector, 0, currentInitializationVector, 0, initializationVector.length);
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = cipherText.length / blockSizeInBytes;
        byte[] decryptedMessage = new byte[cipherText.length];

        for (int i = 0; i < numberOfBlocks; i++) {
            byte[] decryptedBlock = encryptionAlgorithm.decryptOneBlock(Arrays.copyOfRange(cipherText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            for (int j = 0; j < blockSizeInBytes; j++) {
                decryptedBlock[j] ^= currentInitializationVector[j];
            }
            byte[] rightPartOfCurrentInitializationVector = Arrays.copyOfRange(currentInitializationVector, blockSizeInBytes, initializationVector.length);
            System.arraycopy(rightPartOfCurrentInitializationVector, 0, currentInitializationVector, 0, rightPartOfCurrentInitializationVector.length);
            System.arraycopy(cipherText, i * blockSizeInBytes, currentInitializationVector, rightPartOfCurrentInitializationVector.length, blockSizeInBytes);
            System.arraycopy(decryptedBlock, 0, decryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return removePadding(decryptedMessage);
    }

    //TODO оптимизироваать работу с файлами и в ECB
    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), 1048576)) {
            while (bufferedInputStream.available() > 0) {
                byte[] plainData = new byte[Math.min(1048576, bufferedInputStream.available())];
                bufferedInputStream.read(plainData, 0, plainData.length);
                int numberOfBlocksToEncrypt = plainData.length / 16;
                int remainderBytes = plainData.length % 16;
                byte[] cipherData = new byte[(numberOfBlocksToEncrypt + 1) * 16];
                for (int i = 0; i < numberOfBlocksToEncrypt; i++) {
                    byte[] blockOfPlainData = Arrays.copyOfRange(plainData, i * 16, (i + 1) * 16);
                    System.arraycopy(encryptMessage(blockOfPlainData), 0, cipherData, i * 16, 16);
                }
                byte[] paddingBlock = new byte[16];
                if (remainderBytes == 0) {
                    paddingBlock[0] = 1;
                } else {
                    System.arraycopy(plainData, numberOfBlocksToEncrypt * 16, paddingBlock, 0, remainderBytes);
                    paddingBlock[remainderBytes] = 1;
                }
                System.arraycopy(encryptMessage(paddingBlock), 0, cipherData, numberOfBlocksToEncrypt * 16, 16);
                bufferedOutputStream.write(cipherData);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {

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
        byte[] iv = new byte[16];
        Arrays.fill(iv, (byte) 0xff);
        byte[] pt = new byte[16];
        Arrays.fill(pt, (byte) 0xff);
        encryptionAlgorithmWithCipherBlockChaining.setInitializationVector(iv);
        System.out.println(Arrays.toString(encryptionAlgorithmWithCipherBlockChaining.encryptMessage(pt)));
        //16 [-97, 88, -97, 92, -10, 18, 44, 50, -74, -65, -20, 47, 42, -24, -61, 90, -79, 64, -13, 66, 50, -23, -1, 87, -100, 24, 92, 11, 22, -103, -102, -77]
        //10 [53, -74, 12, -121, 15, -26, 37, -120, 40, -3, 9, 112, -91, 17, 40, 38]
    }

}

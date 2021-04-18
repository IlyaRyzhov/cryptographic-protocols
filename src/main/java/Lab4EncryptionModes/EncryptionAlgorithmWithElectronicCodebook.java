package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.createAbsoluteDecryptedFileName;
import static Utils.CommonUtils.createAbsoluteEncryptedFileName;

class EncryptionAlgorithmWithElectronicCodebook extends EncryptionAlgorithmAbstract {

    public EncryptionAlgorithmWithElectronicCodebook(EncryptionAlgorithm encryptionAlgorithm) {
        super(encryptionAlgorithm);
    }

    //TODO Продебажить
    @Override
    public byte[] encryptMessage(byte[] plainText) {
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
            byte[] encryptedBlock;
            if (i != numberOfBlocksInEncryptedMessage - 1)
                encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOfRange(plainText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            else encryptedBlock = encryptionAlgorithm.encryptOneBlock(paddingBlock);
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return encryptedMessage;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        int numberOfBlocks = cipherText.length / blockSizeInBytes;
        byte[] decryptedMessage = new byte[cipherText.length];
        for (int i = 0; i < numberOfBlocks; i++) {
            byte[] decryptedBlock = encryptionAlgorithm.decryptOneBlock(Arrays.copyOfRange(cipherText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            System.arraycopy(decryptedBlock, 0, decryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return removePadding(decryptedMessage);
    }

    /**
     * Шифрует файл в режиме простой замены
     *
     * @param fileToEncrypt        файл, который нужно зашифровать
     * @param pathForEncryptedFile путь, где должен лежать зашифрованный файл
     * @author ILya Ryzhov
     */
    //TODO заменить в енкрипте и декрипте 16 на блоксайзинбайтс
    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
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
                    byte[] blockOfPlainData = Arrays.copyOfRange(plainData, i * blockSizeInBytes, (i + 1) * blockSizeInBytes);
                    System.arraycopy(encryptionAlgorithm.encryptOneBlock(blockOfPlainData), 0, cipherData, i * blockSizeInBytes, blockSizeInBytes);
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
                    bufferedOutputStream.write(encryptionAlgorithm.encryptOneBlock(paddingBlock));
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Расшифровывает файл в режиме простой замены
     *
     * @param fileToDecrypt        файл, который нужно расшифровать, имеет расширение .encrypted
     * @param pathForDecryptedFile путь, где должен лежать расшифрованный файл
     * @author ILya Ryzhov
     */
    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        int blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), 1048576)) {
            while (bufferedInputStream.available() > 0) {
                byte[] cipherData = new byte[Math.min(1048576, bufferedInputStream.available())];
                bufferedInputStream.read(cipherData, 0, cipherData.length);
                int numberOfBlocksToDecrypt = cipherData.length / blockSizeInBytes;
                byte[] plainData = new byte[numberOfBlocksToDecrypt * blockSizeInBytes];
                for (int i = 0; i < numberOfBlocksToDecrypt; i++) {
                    byte[] blockOfCipherData = Arrays.copyOfRange(cipherData, i * blockSizeInBytes, (i + 1) * blockSizeInBytes);
                    System.arraycopy(encryptionAlgorithm.decryptOneBlock(blockOfCipherData), 0, plainData, i * blockSizeInBytes, blockSizeInBytes);
                }
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

    public static void main(String[] args) {
        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithElectronicCodebook electronicCodebook = new EncryptionAlgorithmWithElectronicCodebook(twoFish);
        electronicCodebook.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");
    }
}

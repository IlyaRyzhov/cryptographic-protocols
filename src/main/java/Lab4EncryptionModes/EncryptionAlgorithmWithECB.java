package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;
import Lab1EncryptionAlgorithm.TwoFish;

import java.io.*;
import java.util.Arrays;

import static Utils.CommonUtils.getAbsoluteDecryptedFileName;
import static Utils.CommonUtils.getAbsoluteEncryptedFileName;

class EncryptionAlgorithmWithECB extends EncryptionAlgorithmAbstract {

    public EncryptionAlgorithmWithECB(EncryptionAlgorithm encryptionAlgorithm) {
        super(encryptionAlgorithm);
    }

    @Override
    public byte[] encryptMessage(byte[] plainText) {
        int numberOfBlocksInEncryptedMessage = (plainText.length / blockSizeInBytes) + 1;
        byte[] encryptedMessage = new byte[numberOfBlocksInEncryptedMessage * blockSizeInBytes];
        byte[] paddingBlock = getPaddingBlock(plainText);
        byte[] encryptedBlock;
        for (int i = 0; i < numberOfBlocksInEncryptedMessage; i++) {
            if (i != numberOfBlocksInEncryptedMessage - 1)
                encryptedBlock = encryptionAlgorithm.encryptOneBlock(Arrays.copyOfRange(plainText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
            else encryptedBlock = encryptionAlgorithm.encryptOneBlock(paddingBlock);
            System.arraycopy(encryptedBlock, 0, encryptedMessage, i * blockSizeInBytes, blockSizeInBytes);
        }
        return encryptedMessage;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        int numberOfBlocks = cipherText.length / blockSizeInBytes;
        byte[] decryptedMessage = new byte[cipherText.length];
        byte[] decryptedBlock;
        for (int i = 0; i < numberOfBlocks; i++) {
            decryptedBlock = encryptionAlgorithm.decryptOneBlock(Arrays.copyOfRange(cipherText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes));
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
    //TODO переделать работу с файлом
    @Override
    public void encryptFile(File fileToEncrypt, String pathForEncryptedFile) {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToEncrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteEncryptedFileName(fileToEncrypt, pathForEncryptedFile)), 1048576)) {
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
    //TODO переделать работу с файлом
    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(getAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), 1048576)) {
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
        EncryptionAlgorithmWithECB electronicCodebook = new EncryptionAlgorithmWithECB(twoFish);
        electronicCodebook.decryptFile(new File("C:\\Users\\fvd\\Desktop\\100MB.txt.encrypted"), "C:\\Users\\fvd\\Desktop");
    }
}

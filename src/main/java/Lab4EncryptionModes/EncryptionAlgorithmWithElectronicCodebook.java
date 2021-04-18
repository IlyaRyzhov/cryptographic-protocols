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
        byte[] paddingBlock = new byte[16];
        if (remainderBytes == 0) {
            paddingBlock[0] = 1;
        } else {
            System.arraycopy(plainText, (numberOfBlocksInEncryptedMessage - 1) * 16, paddingBlock, 0, remainderBytes);
            paddingBlock[remainderBytes] = 1;
        }
        for (int i = 0; i < numberOfBlocksInEncryptedMessage; i++) {
            byte[] encryptedBlock = new byte[blockSizeInBytes];
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
    //TODO проверить на соответствие режиму шифрования
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

    /**
     * Расшифровывает файл в режиме простой замены
     *
     * @param fileToDecrypt        файл, который нужно расшифровать, имеет расширение .encrypted
     * @param pathForDecryptedFile путь, где должен лежать расшифрованный файл
     * @author ILya Ryzhov
     */
    @Override
    public void decryptFile(File fileToDecrypt, String pathForDecryptedFile) {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(fileToDecrypt), 1048576);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(createAbsoluteDecryptedFileName(fileToDecrypt, pathForDecryptedFile)), 1048576)) {
            while (bufferedInputStream.available() > 0) {
                byte[] cipherData = new byte[Math.min(1048576, bufferedInputStream.available())];
                bufferedInputStream.read(cipherData, 0, cipherData.length);
                int numberOfBlocksToDecrypt = cipherData.length / 16;
                byte[] plainData = new byte[numberOfBlocksToDecrypt * 16];
                for (int i = 0; i < numberOfBlocksToDecrypt; i++) {
                    byte[] blockOfCipherData = Arrays.copyOfRange(cipherData, i * 16, (i + 1) * 16);
                    System.arraycopy(decryptMessage(blockOfCipherData), 0, plainData, i * 16, 16);
                }
                if (bufferedInputStream.available() > 0)
                    bufferedOutputStream.write(plainData);
                else {
                    byte[] lastBlock = new byte[16];
                    System.arraycopy(plainData, (numberOfBlocksToDecrypt - 1) * 16, lastBlock, 0, 16);
                    int indexOfLastOne = 0;
                    for (int i = 15; i >= 0; i--) {
                        if (lastBlock[i] == 1) {
                            indexOfLastOne = i;
                            break;
                        }
                    }
                    bufferedOutputStream.write(plainData, 0, plainData.length - 16);
                    bufferedOutputStream.write(Arrays.copyOfRange(lastBlock, 0, indexOfLastOne));
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        TwoFish twoFish = new TwoFish(new long[2]);
        EncryptionAlgorithmWithElectronicCodebook electronicCodebook = new EncryptionAlgorithmWithElectronicCodebook(twoFish);
        byte[] pt = new byte[48];
        //Arrays.fill(pt, (byte) 0xff);
        byte[] ct = electronicCodebook.encryptMessage(pt);
        for (int i = 0; i < ct.length; i++) {
            System.out.print(Integer.toHexString(ct[i] & 0xff));
        }
        System.out.println();
        pt = electronicCodebook.decryptMessage(ct);
        for (int i = 0; i < pt.length; i++) {
            System.out.print(Integer.toHexString(pt[i] & 0xff));
        }
        System.out.println();
        //ct = electronicCodebook.encryptMessage(pt);

    }
}

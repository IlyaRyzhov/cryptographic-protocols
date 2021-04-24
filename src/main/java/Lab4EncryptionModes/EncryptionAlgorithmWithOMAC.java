package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.io.File;
import java.util.Arrays;

import static Utils.EncryptionModesUtils.multiplyPolynomialsModPrimitivePolynomial;
import static Utils.EncryptionModesUtils.xorByteArrays;

public class EncryptionAlgorithmWithOMAC  {
/*    private final int gammaLengthInBytes;
    private final byte[] auxiliaryKeyOne;
    private final byte[] auxiliaryKeyTwo;
    private static final byte[] primitivePolynomial;

    static {
        primitivePolynomial = new byte[17];
        primitivePolynomial[0] = 1;
        primitivePolynomial[16] = (byte) 0b10000111;
    }

    public EncryptionAlgorithmWithOMAC(EncryptionAlgorithm encryptionAlgorithm, int gammaLengthInBytes) {
        super(encryptionAlgorithm);
        this.gammaLengthInBytes = gammaLengthInBytes;
        byte[] rVector = encryptionAlgorithm.encryptOneBlock(new byte[blockSizeInBytes]);
        byte[] firstDegreePolynomial = new byte[primitivePolynomial.length - 1];
        firstDegreePolynomial[firstDegreePolynomial.length - 1] = 0b00000010;
        auxiliaryKeyOne = multiplyPolynomialsModPrimitivePolynomial(rVector, firstDegreePolynomial, primitivePolynomial);
        auxiliaryKeyTwo = multiplyPolynomialsModPrimitivePolynomial(auxiliaryKeyOne, firstDegreePolynomial, primitivePolynomial);
    }

    //TODO переделать дополнение?
//фикс дополнения
    @Override
    public byte[] encryptMessage(byte[] plainText) {
        byte[] previousCipherBlock = new byte[blockSizeInBytes];
        byte[] currentCipherBlock;
        int numberOfBlocksInPlainText = (int) Math.ceil((double) plainText.length / blockSizeInBytes) - 1;
        int remainderBytes = plainText.length % blockSizeInBytes;
        byte[] blockOfPlainText = new byte[blockSizeInBytes];
        byte[] result = new byte[plainText.length + gammaLengthInBytes];
        for (int i = 0; i < numberOfBlocksInPlainText; i++) {
            System.arraycopy(plainText, i * blockSizeInBytes, blockOfPlainText, 0, blockSizeInBytes);
            xorByteArrays(blockOfPlainText, previousCipherBlock);
            currentCipherBlock = encryptionAlgorithm.encryptOneBlock(blockOfPlainText);
            System.arraycopy(currentCipherBlock, 0, result, i * blockSizeInBytes, blockSizeInBytes);
            previousCipherBlock = Arrays.copyOf(currentCipherBlock, currentCipherBlock.length);
        }
        if (remainderBytes != 0) {
            System.arraycopy(plainText, plainText.length - remainderBytes, blockOfPlainText, 0, remainderBytes);
        } else System.arraycopy(plainText, plainText.length - blockSizeInBytes, blockOfPlainText, 0, blockSizeInBytes);
        xorByteArrays(blockOfPlainText, previousCipherBlock);
        xorByteArrays(blockOfPlainText, remainderBytes == 0 ? auxiliaryKeyOne : auxiliaryKeyTwo);
        currentCipherBlock = encryptionAlgorithm.encryptOneBlock(blockOfPlainText);
        System.arraycopy(currentCipherBlock, 0, result, numberOfBlocksInPlainText * blockSizeInBytes, blockSizeInBytes);
        byte[] imitationInsert = Arrays.copyOf(currentCipherBlock, gammaLengthInBytes);
        System.arraycopy(imitationInsert, 0, result, plainText.length, gammaLengthInBytes);
        return result;
    }

    @Override
    public byte[] decryptMessage(byte[] cipherText) {
        byte[] plainBlock;
        byte[] previousCipherBlock = new byte[blockSizeInBytes];
        int numberOfPlainBlocks = (cipherText.length - gammaLengthInBytes) / blockSizeInBytes - 1;
        byte[] plainMessage = new byte[(numberOfPlainBlocks + 1) * blockSizeInBytes];
        byte[] currentCipherBlock;
        for (int i = 0; i < numberOfPlainBlocks; i++) {
            currentCipherBlock = Arrays.copyOfRange(cipherText, i * blockSizeInBytes, (i + 1) * blockSizeInBytes);
            plainBlock = encryptionAlgorithm.decryptOneBlock(currentCipherBlock);
            xorByteArrays(plainBlock, previousCipherBlock);
            System.arraycopy(plainBlock, 0, plainMessage, i * blockSizeInBytes, blockSizeInBytes);
            System.arraycopy(currentCipherBlock, 0, previousCipherBlock, 0, previousCipherBlock.length);
        }
        currentCipherBlock = Arrays.copyOfRange(cipherText, blockSizeInBytes * numberOfPlainBlocks, cipherText.length - gammaLengthInBytes);
        byte[] imitationInsert = Arrays.copyOfRange(cipherText, plainMessage.length, cipherText.length);
        plainBlock = encryptionAlgorithm.decryptOneBlock(currentCipherBlock);
        xorByteArrays(plainBlock, previousCipherBlock);

        return plainMessage;
    }

    //TODO Доделать
    private byte[] decryptLastBlock(byte[] lastBlock, byte[] previousCipherBlock, byte[] imitationInsert) {
        byte[] plainBlock = encryptionAlgorithm.decryptOneBlock(lastBlock);
        xorByteArrays(plainBlock, previousCipherBlock);
        xorByteArrays(plainBlock, auxiliaryKeyOne);
        plainBlock = removePadding(plainBlock);
        if (plainBlock.length != blockSizeInBytes)
            return null;
        byte[] computedImitationInsert = Arrays.copyOf(plainBlock, plainBlock.length);
        xorByteArrays(computedImitationInsert, previousCipherBlock);
        xorByteArrays(computedImitationInsert, auxiliaryKeyOne);
        computedImitationInsert = Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(computedImitationInsert), gammaLengthInBytes);
        return null;
    }*/
}

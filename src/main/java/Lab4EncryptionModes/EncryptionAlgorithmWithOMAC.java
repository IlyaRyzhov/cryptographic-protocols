package Lab4EncryptionModes;

import Lab1EncryptionAlgorithm.EncryptionAlgorithm;

import java.util.Arrays;

import static Utils.EncryptionModesUtils.multiplyPolynomialsModPrimitivePolynomial;
import static Utils.EncryptionModesUtils.xorByteArrays;

public class EncryptionAlgorithmWithOMAC {
    private final EncryptionAlgorithm encryptionAlgorithm;
    private final int blockSizeInBytes;
    private final int gammaLengthInBytes;
    private final byte[] auxiliaryKeyOne;
    private final byte[] auxiliaryKeyTwo;
    private static final byte[] primitivePolynomial;

    static {
        primitivePolynomial = new byte[17];
        primitivePolynomial[0] = 1;
        primitivePolynomial[16] = (byte) 0b10000111;
    }

    public EncryptionAlgorithmWithOMAC(EncryptionAlgorithm encryptionAlgorithm, int gammaLengthInBytes) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        this.gammaLengthInBytes = gammaLengthInBytes;
        byte[] rVector = encryptionAlgorithm.encryptOneBlock(new byte[blockSizeInBytes]);
        byte[] firstDegreePolynomial = new byte[primitivePolynomial.length - 1];
        firstDegreePolynomial[firstDegreePolynomial.length - 1] = 0b00000010;
        auxiliaryKeyOne = multiplyPolynomialsModPrimitivePolynomial(rVector, firstDegreePolynomial, primitivePolynomial);
        auxiliaryKeyTwo = multiplyPolynomialsModPrimitivePolynomial(auxiliaryKeyOne, firstDegreePolynomial, primitivePolynomial);
    }

    //TODO переделать дополнение? Рефакторить
//фикс дополнения
    public byte[] getImitationInsertFromMessage(byte[] plainMessage) {
        byte[] previousCipherBlock = new byte[blockSizeInBytes];
        byte[] currentCipherBlock;
        int numberOfBlocksInPlainText = (int) Math.ceil((double) plainMessage.length / blockSizeInBytes) - 1;
        int remainderBytes = plainMessage.length % blockSizeInBytes;
        byte[] blockOfPlainText = new byte[blockSizeInBytes];
        for (int i = 0; i < numberOfBlocksInPlainText; i++) {
            System.arraycopy(plainMessage, i * blockSizeInBytes, blockOfPlainText, 0, blockSizeInBytes);
            xorByteArrays(blockOfPlainText, previousCipherBlock);
            currentCipherBlock = encryptionAlgorithm.encryptOneBlock(blockOfPlainText);
            previousCipherBlock = Arrays.copyOf(currentCipherBlock, currentCipherBlock.length);
        }
        if (remainderBytes != 0) {
            System.arraycopy(plainMessage, plainMessage.length - remainderBytes, blockOfPlainText, 0, remainderBytes);
        } else
            System.arraycopy(plainMessage, plainMessage.length - blockSizeInBytes, blockOfPlainText, 0, blockSizeInBytes);
        xorByteArrays(blockOfPlainText, previousCipherBlock);
        xorByteArrays(blockOfPlainText, remainderBytes == 0 ? auxiliaryKeyOne : auxiliaryKeyTwo);
        currentCipherBlock = encryptionAlgorithm.encryptOneBlock(blockOfPlainText);
        return Arrays.copyOf(currentCipherBlock, gammaLengthInBytes);
    }
}

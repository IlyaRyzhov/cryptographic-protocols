package encryptionModes;

import encryptionAlgorithm.EncryptionAlgorithm;

import java.io.*;
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
    protected int bufferSize;
    private static final int DEFAULT_BUFFER_SIZE = 1048576;

    static {
        primitivePolynomial = new byte[17];
        primitivePolynomial[0] = 1;
        primitivePolynomial[16] = (byte) 0b10000111;
    }

    /**
     * @param encryptionAlgorithm класс, реализующий интерфейс EncryptionAlgorithm
     * @param gammaLengthInBytes  длина гаммы в байтах
     * @author Ilya Ryzhov
     */
    public EncryptionAlgorithmWithOMAC(EncryptionAlgorithm encryptionAlgorithm, int gammaLengthInBytes) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.blockSizeInBytes = encryptionAlgorithm.getBlockSizeInBytes();
        this.gammaLengthInBytes = gammaLengthInBytes;
        setBufferSize(DEFAULT_BUFFER_SIZE);
        byte[] rVector = encryptionAlgorithm.encryptOneBlock(new byte[blockSizeInBytes]);
        byte[] firstDegreePolynomial = new byte[primitivePolynomial.length - 1];
        firstDegreePolynomial[firstDegreePolynomial.length - 1] = 0b00000010;
        auxiliaryKeyOne = multiplyPolynomialsModPrimitivePolynomial(rVector, firstDegreePolynomial, primitivePolynomial);
        auxiliaryKeyTwo = multiplyPolynomialsModPrimitivePolynomial(auxiliaryKeyOne, firstDegreePolynomial, primitivePolynomial);
    }

    /**
     * Вычисляет имитовставку от сообщения
     *
     * @param plainMessage сообщение, от которого нужно получить имитовставку
     * @return имитовставка
     * @author Ilya Ryzhov
     */
    public byte[] getImitationInsertFromMessage(byte[] plainMessage) {
        byte[] previousEncryptedBlock = new byte[blockSizeInBytes];
        int numberOfBlocksInPlainMessageWithoutLastBlock = (int) Math.ceil((double) plainMessage.length / blockSizeInBytes) - 1;
        getImitationInsertWithoutProcessingLastBlock(plainMessage, previousEncryptedBlock, numberOfBlocksInPlainMessageWithoutLastBlock);
        return processLastBlock(plainMessage, previousEncryptedBlock, numberOfBlocksInPlainMessageWithoutLastBlock);
    }

    private void getImitationInsertWithoutProcessingLastBlock(byte[] plainMessage, byte[] previousEncryptedBlock, int numberOfProcessingBlock) {
        byte[] currentEncryptedBlock;
        byte[] blockOfPlainMessage = new byte[blockSizeInBytes];
        for (int i = 0; i < numberOfProcessingBlock; i++) {
            System.arraycopy(plainMessage, i * blockSizeInBytes, blockOfPlainMessage, 0, blockSizeInBytes);
            xorByteArrays(blockOfPlainMessage, previousEncryptedBlock, blockSizeInBytes);
            currentEncryptedBlock = encryptionAlgorithm.encryptOneBlock(blockOfPlainMessage);
            System.arraycopy(currentEncryptedBlock, 0, previousEncryptedBlock, 0, blockSizeInBytes);
        }
    }

    private byte[] processLastBlock(byte[] plainMessage, byte[] previousEncryptedBlock, int offsetInBlocksInPlainMessage) {
        int remainderBytes = plainMessage.length % blockSizeInBytes;
        byte[] lastBlockOfPlainMessage = Arrays.copyOfRange(plainMessage, offsetInBlocksInPlainMessage * blockSizeInBytes, plainMessage.length);
        if (remainderBytes != 0) {
            lastBlockOfPlainMessage = Arrays.copyOf(lastBlockOfPlainMessage, blockSizeInBytes);
            lastBlockOfPlainMessage[remainderBytes] = 1;
        }
        xorByteArrays(lastBlockOfPlainMessage, previousEncryptedBlock, blockSizeInBytes);
        xorByteArrays(lastBlockOfPlainMessage, remainderBytes == 0 ? auxiliaryKeyOne : auxiliaryKeyTwo, blockSizeInBytes);
        return Arrays.copyOf(encryptionAlgorithm.encryptOneBlock(lastBlockOfPlainMessage), gammaLengthInBytes);
    }

    /**
     * Вычисляет имитовставку от файла
     *
     * @param file файл, от которого нужно получить имитовставку
     * @return имитовставка
     * @author Ilya Ryzhov
     */
    public byte[] getImitationInsertFromFile(File file) {
        byte[] imitationInsert = new byte[gammaLengthInBytes];
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file), bufferSize)) {

            byte[] previousEncryptedBlock = new byte[blockSizeInBytes];
            byte[] plainData;
            while (bufferedInputStream.available() > 0) {
                plainData = bufferedInputStream.readNBytes(bufferSize);
                if (bufferedInputStream.available() > 0) {
                    getImitationInsertWithoutProcessingLastBlock(plainData, previousEncryptedBlock, plainData.length / blockSizeInBytes);
                } else {
                    int numberOfBlocksInPlainMessageWithoutLastBlock = (int) Math.ceil((double) plainData.length / blockSizeInBytes) - 1;
                    getImitationInsertWithoutProcessingLastBlock(plainData, previousEncryptedBlock, numberOfBlocksInPlainMessageWithoutLastBlock);
                    imitationInsert = processLastBlock(plainData, previousEncryptedBlock, numberOfBlocksInPlainMessageWithoutLastBlock);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return imitationInsert;
    }

    /**
     * @see EncryptionAlgorithmAbstract
     */
    public void setBufferSize(int bufferSize) {
        this.bufferSize = Math.max(bufferSize - bufferSize % blockSizeInBytes, blockSizeInBytes);
    }

    /**
     * Возвращает используемый в режиме экземпляр класса, реализующего EncryptionAlgorithm
     *
     * @return экземпляр класса, реализующего EncryptionAlgorithm
     * @author Ilya Ryzhov
     */
    public EncryptionAlgorithm getEncryptionAlgorithm() {
        return encryptionAlgorithm;
    }
}

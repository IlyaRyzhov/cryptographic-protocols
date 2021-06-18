package hashAlgorithm;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

import static hashAlgorithm.BlueMidnightWishDigestSize.*;
import static Utils.CommonUtils.convertLongArrayToByteArray;

abstract class BlueMidnightWishAbstract implements HashFunction {
    private int expandRoundsOne = 2;
    private int expandRoundsTwo = 14;
    private final BlueMidnightWishDigestSize digestSize;
    private int numberOfBytesInDigest;

    protected BlueMidnightWishAbstract(BlueMidnightWishDigestSize digestSize) {
        this.digestSize = digestSize;
    }

    /**
     * @see HashFunction
     */
    @Override
    public final byte[] computeHash(byte[] message) {
        byte[] result = computeHashWithoutResetDoublePipe(message, message.length);
        initializeInitialDoublePipe();
        return result;
    }

    /**
     * Вычисляет хеш сообщения, используя totalLengthOfMessage как длину сообщения при дополнении сообщения
     *
     * @param message              хешируемое сообщение
     * @param totalLengthOfMessage общая длина сообщения, которую надо использовать при дополнении сообщения
     * @return хеш сообщения
     * @author Ilya Ryzhov
     */
    protected final byte[] computeHash(byte[] message, long totalLengthOfMessage) {
        byte[] result = computeHashWithoutResetDoublePipe(message, totalLengthOfMessage);
        initializeInitialDoublePipe();
        return result;
    }

    /**
     * Вычисляет хеш сообщения, не выставляя значения двойной трубы в исходное состояние
     *
     * @param message              хеширумое сообщение
     * @param totalLengthOfMessage общая длина сообщения, которую надо использовать при дополнении сообщения
     * @return хеш сообщения
     * @author Ilya Ryzhov
     */
    protected abstract byte[] computeHashWithoutResetDoublePipe(byte[] message, long totalLengthOfMessage);

    /**
     * Одна итерация функции сжатия
     *
     * @param messageBlock блок сообщения, к которому применяется операция сжатия
     * @author Ilya Ryzhov
     */
    protected abstract void compressIteration(byte[] messageBlock);

    /**
     * Применяет функцию сжатия до тех пор, пока не дойдет до последнего блока дополненного  сообщения
     *
     * @param message хешируемое сообщение
     * @return хеш сообщения без учета последнего блока дополненного сообщения
     * @author Ilya Ryzhov
     */
    protected final byte[] repeatCompressIterationUntilLastBlock(byte[] message) {
        int blockSize = getBlockSize();
        int numberOfBlocks = message.length / blockSize;
        for (int i = 0; i < numberOfBlocks * blockSize; i += blockSize) {
            byte[] messageBlock = new byte[blockSize];
            System.arraycopy(message, i, messageBlock, 0, blockSize);
            compressIteration(messageBlock);
        }
        byte[] lastBlock = new byte[message.length - numberOfBlocks * blockSize];
        System.arraycopy(message, numberOfBlocks * blockSize, lastBlock, 0, message.length % blockSize);
        return lastBlock;
    }

    /**
     * Устанавлиает значения трубы в исходное состояние
     *
     * @author Ilya Ryzhov
     */
    protected abstract void initializeInitialDoublePipe();

    /**
     * Дополняет сообщение до кратности длине блока
     *
     * @param message                    дополняемое сообщение
     * @param lengthOfMessageBLockInBits длина блока сообщения в битах
     * @param lengthOfMessageInBits      длина всего дополняемого сообщения в битах(для записи в последнем блоке)
     * @return дополненное сообщение
     * @author Ilya Ryzhov
     */
    protected final byte[] padMessage(byte[] message, int lengthOfMessageBLockInBits, long lengthOfMessageInBits) {
        int k = solvePaddingEquation(lengthOfMessageInBits, lengthOfMessageBLockInBits);
        byte[] paddingBlockWithoutLastPart = new byte[(k + 1) / 8];
        paddingBlockWithoutLastPart[0] = -128;
        byte[] lastPart = convertLongArrayToByteArray(new long[]{Long.reverseBytes(lengthOfMessageInBits)});
        byte[] resultMessage = new byte[message.length + paddingBlockWithoutLastPart.length + 8];
        System.arraycopy(message, 0, resultMessage, 0, message.length);
        System.arraycopy(paddingBlockWithoutLastPart, 0, resultMessage, message.length, paddingBlockWithoutLastPart.length);
        System.arraycopy(lastPart, 0, resultMessage, message.length + paddingBlockWithoutLastPart.length, lastPart.length);
        return resultMessage;
    }

    /**
     * Решает уравнение, определяющее сколькими нулями будет дополнен блок
     *
     * @param lengthOfMessage            длина сообщения в битах
     * @param lengthOfMessageBLockInBits длина блока сообщения в битах
     * @return число нулей, которыми нужно дополнить сообщение
     * @author Ilya Ryzhov
     */
    protected final int solvePaddingEquation(long lengthOfMessage, int lengthOfMessageBLockInBits) {
        int l = (int) (lengthOfMessage % lengthOfMessageBLockInBits);
        int k = (lengthOfMessageBLockInBits - 64) - (l + 1);
        return k >= 0 ? k : k + lengthOfMessageBLockInBits;
    }

    /**
     * Показывает сколько раз в алгоритме применяется функция expandOne
     *
     * @return количество применений функции expandOne
     * @author Ilya Ryzhov
     */
    protected final int getExpandRoundsOne() {
        return expandRoundsOne;
    }

    /**
     * Изменяет количество применений функции expandOne
     *
     * @author Ilya Ryzhov
     */
    protected final void setExpandRoundsOne(int expandRoundsOne) {
        this.expandRoundsOne = expandRoundsOne;
        this.expandRoundsTwo = 16 - expandRoundsOne;
    }

    /**
     * Показывает сколько раз в алгоритме применяется функция expandTwo
     *
     * @return количество применений функции expandTwo
     * @author Ilya Ryzhov
     */
    protected final int getExpandRoundsTwo() {
        return expandRoundsTwo;
    }

    /**
     * Изменяет количество применений функции expandTwo
     *
     * @author Ilya Ryzhov
     */
    protected final void setExpandRoundsTwo(int expandRoundsTwo) {
        this.expandRoundsTwo = expandRoundsTwo;
        this.expandRoundsOne = 16 - expandRoundsTwo;
    }

    /**
     * Показывает текущую реализацию алгоритма BMW
     *
     * @return размер выхода функции хеширования
     * @author Ilya Ryzhov
     */
    protected final BlueMidnightWishDigestSize getDigestSize() {
        return digestSize;
    }

    /**
     * Устанавливает реализацию алгоритма BMW
     *
     * @param numberOfBytesInDigest необходимая длина выхода функции хеширования
     * @author Ilya Ryzhov
     */
    protected final void setOutputLength(int numberOfBytesInDigest) {
        this.numberOfBytesInDigest = numberOfBytesInDigest;
    }

    /**
     * @see HashFunction
     */
    @Override
    public final int getBlockSize() {
        return (digestSize == BLUE_MIDNIGHT_WISH_224 || digestSize == BLUE_MIDNIGHT_WISH_256) ? 64 : 128;
    }

    /**
     * @see HashFunction
     */
    @Override
    public final int getOutputLength() {
        return numberOfBytesInDigest;
    }

    /**
     * @see HashFunction
     */
    @Override
    public final byte[] computeHash(File hashableFile) {
        byte[] hashOfFile = new byte[getOutputLength()];
        long fileLength = hashableFile.length();
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(hashableFile), 1048576)) {
            while (bufferedInputStream.available() > 0) {
                byte[] data = bufferedInputStream.readNBytes(1048576);
                if (bufferedInputStream.available() > 0)
                    repeatCompressIterationUntilLastBlock(data);
                else {
                    hashOfFile = computeHash(data, fileLength);
                }
            }
        } catch (
                IOException e) {
            e.printStackTrace();
        }
        return hashOfFile;
    }
}

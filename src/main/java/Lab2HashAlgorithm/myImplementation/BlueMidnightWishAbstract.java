package Lab2HashAlgorithm.myImplementation;

import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.*;
import static Utils.CommonUtils.convertLongArrayToByteArray;

public abstract class BlueMidnightWishAbstract implements HashFunction {
    private int expandRoundsOne = 2;
    private int expandRoundsTwo = 14;
    private final BlueMidnightWishDigestSize digestSize;
    private int numberOfBytesInDigest;

    protected BlueMidnightWishAbstract(BlueMidnightWishDigestSize digestSize) {
        this.digestSize = digestSize;
    }

    public final byte[] computeHash(byte[] message) {
        byte[] result = computeHashWithoutResetDoublePipe(message);
        initializeInitialDoublePipe();
        return result;
    }

    protected abstract byte[] computeHashWithoutResetDoublePipe(byte[] message);

    protected abstract void compressIteration(byte[] messageBlock);

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

    protected abstract void initializeInitialDoublePipe();

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

    protected final int solvePaddingEquation(long lengthOfMessage, int lengthOfMessageBLockInBits) {
        int l = (int) (lengthOfMessage % lengthOfMessageBLockInBits);
        int k = (lengthOfMessageBLockInBits - 64) - (l + 1);
        return k >= 0 ? k : k + lengthOfMessageBLockInBits;
    }

    protected final int getExpandRoundsOne() {
        return expandRoundsOne;
    }

    protected final void setExpandRoundsOne(int expandRoundsOne) {
        this.expandRoundsOne = expandRoundsOne;
        this.expandRoundsTwo = 16 - expandRoundsOne;
    }

    protected final int getExpandRoundsTwo() {
        return expandRoundsTwo;
    }

    protected final void setExpandRoundsTwo(int expandRoundsTwo) {
        this.expandRoundsTwo = expandRoundsTwo;
        this.expandRoundsOne = 16 - expandRoundsTwo;
    }

    protected final BlueMidnightWishDigestSize getDigestSize() {
        return digestSize;
    }

    protected final void setOutputLength(int numberOfBytesInDigest) {
        this.numberOfBytesInDigest = numberOfBytesInDigest;
    }

    @Override
    public final int getBlockSize() {
        return (digestSize == BLUE_MIDNIGHT_WISH_224 || digestSize == BLUE_MIDNIGHT_WISH_256) ? 64 : 128;
    }


    @Override

    public final int getOutputLength() {
        return numberOfBytesInDigest;
    }
}

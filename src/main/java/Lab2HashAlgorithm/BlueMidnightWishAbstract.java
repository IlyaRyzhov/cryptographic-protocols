package Lab2HashAlgorithm;

import static Utils.CommonUtils.convertLongArrayToByteArray;

public abstract class BlueMidnightWishAbstract implements HashFunction {
    private int expandRoundsOne = 2;
    private int expandRoundsTwo = 14;
    private final BlueMidnightWishDigestSize digestSize;

    private int numberOfBytesInDigest;


    protected int solvePaddingEquation(long lengthOfMessage, int lengthOfMessageBLockInBits) {
        int l = (int) (lengthOfMessage % lengthOfMessageBLockInBits);
        int k = (lengthOfMessageBLockInBits - 64) - (l + 1);
        return k >= 0 ? k : k + lengthOfMessageBLockInBits;
    }

    protected byte[] padMessage(byte[] message, int lengthOfMessageBLockInBits) {
        long l = message.length * 8L;
        int k = solvePaddingEquation(l, lengthOfMessageBLockInBits);
        byte[] paddingBlockWithoutLastPart = new byte[(k + 1) / 8];
        paddingBlockWithoutLastPart[0] = -128;
        byte[] lastPart = convertLongArrayToByteArray(new long[]{Long.reverseBytes(l)});
        byte[] resultMessage = new byte[message.length + paddingBlockWithoutLastPart.length + 8];
        System.arraycopy(message, 0, resultMessage, 0, message.length);
        System.arraycopy(paddingBlockWithoutLastPart, 0, resultMessage, message.length, paddingBlockWithoutLastPart.length);
        System.arraycopy(lastPart, 0, resultMessage, message.length + paddingBlockWithoutLastPart.length, lastPart.length);
        return resultMessage;
    }


    protected BlueMidnightWishAbstract(BlueMidnightWishDigestSize digestSize) {
        this.digestSize = digestSize;
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

    protected final int getNumberOfBytesInDigest() {
        return numberOfBytesInDigest;
    }

    protected final void setNumberOfBytesInDigest(int numberOfBytesInDigest) {
        this.numberOfBytesInDigest = numberOfBytesInDigest;
    }
}

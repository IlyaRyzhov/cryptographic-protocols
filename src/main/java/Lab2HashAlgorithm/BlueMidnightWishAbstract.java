package Lab2HashAlgorithm;

public abstract class BlueMidnightWishAbstract {
    private int expandRoundsOne = 2;
    private int expandRoundsTwo = 14;
    private final BlueFishDigestSize digestSize;

    private int numberOfBytesInDigest;

    protected abstract byte[] padMessage(byte[] message);

    protected abstract int solvePaddingEquation(long lengthOfMessage);

    protected BlueMidnightWishAbstract(BlueFishDigestSize digestSize) {
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

    protected final BlueFishDigestSize getDigestSize() {
        return digestSize;
    }

    protected final int getNumberOfBytesInDigest() {
        return numberOfBytesInDigest;
    }

    protected final void setNumberOfBytesInDigest(int numberOfBytesInDigest) {
        this.numberOfBytesInDigest = numberOfBytesInDigest;
    }
}

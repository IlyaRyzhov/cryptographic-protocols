package Lab2HashAlgorithm;

public abstract class BlueMidnightWishAbstract {
    private int expandRoundsOne = 2;
    private int expandRoundsTwo = 14;
    private final BlueFishDigestSize digestSize;

    protected abstract byte[] padMessage(byte[] message);

    protected abstract int solvePaddingEquation(long lengthOfMessage);

    protected BlueMidnightWishAbstract(BlueFishDigestSize digestSize) {
        this.digestSize = digestSize;
    }

    protected int getExpandRoundsOne() {
        return expandRoundsOne;
    }

    protected void setExpandRoundsOne(int expandRoundsOne) {
        this.expandRoundsOne = expandRoundsOne;
        this.expandRoundsTwo = 16 - expandRoundsOne;
    }

    protected int getExpandRoundsTwo() {
        return expandRoundsTwo;
    }

    protected void setExpandRoundsTwo(int expandRoundsTwo) {
        this.expandRoundsTwo = expandRoundsTwo;
        this.expandRoundsOne = 16 - expandRoundsTwo;
    }

    protected BlueFishDigestSize getDigestSize() {
        return digestSize;
    }

}

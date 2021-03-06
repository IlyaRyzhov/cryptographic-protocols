package hashAlgorithm;

import java.io.File;

import static hashAlgorithm.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_224;
import static hashAlgorithm.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_256;

public class BlueMidnightWish implements HashFunction {
    private BlueMidnightWishAbstract blueMidnightWishImplementation;

    public BlueMidnightWish(BlueMidnightWishDigestSize blueMidnightWishDigestSize) {
        setOutputSize(blueMidnightWishDigestSize);
    }

    /**
     * @see HashFunction
     */
    @Override
    public byte[] computeHash(byte[] message) {
        return blueMidnightWishImplementation.computeHash(message);
    }

    /**
     * Изменяет реализацию(длину выхода) алгоритма BMW
     *
     * @param blueMidnightWishDigestSize новый размер выхода функции хеширования
     * @author Ilya Ryzhov
     */
    public void setOutputSize(BlueMidnightWishDigestSize blueMidnightWishDigestSize) {
        if (blueMidnightWishDigestSize == BLUE_MIDNIGHT_WISH_224 || blueMidnightWishDigestSize == BLUE_MIDNIGHT_WISH_256) {
            blueMidnightWishImplementation = new BlueMidnightWishWithIntegerWord(blueMidnightWishDigestSize);
        } else blueMidnightWishImplementation = new BlueMidnightWishWithLongWord(blueMidnightWishDigestSize);
    }

    /**
     * @see HashFunction
     */
    @Override
    public int getBlockSize() {
        return blueMidnightWishImplementation.getBlockSize();
    }

    /**
     * @see HashFunction
     */
    @Override
    public int getOutputLength() {
        return blueMidnightWishImplementation.getOutputLength();
    }

    /**
     * @see HashFunction
     */
    @Override
    public byte[] computeHash(File file) {
        return blueMidnightWishImplementation.computeHash(file);
    }
}

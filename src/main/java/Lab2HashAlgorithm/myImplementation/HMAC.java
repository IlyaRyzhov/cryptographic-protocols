package Lab2HashAlgorithm.myImplementation;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HMAC {
    private final int blockSizeInBytes;
    private final HashFunction hashFunction;
    private final byte[] ipad;
    private final byte[] opad;
    private byte[] key;
    private final byte[] alteredKey;
    private final int hashOutputLengthInBytes;
    private final byte[] keyXoredWithIpad;
    private final byte[] keyXoredWithOpad;

    public HMAC(HashFunction hashFunction, byte[] key) {
        this.hashFunction = hashFunction;
        this.key = key;
        this.blockSizeInBytes = this.hashFunction.getBlockSize();
        this.hashOutputLengthInBytes = this.hashFunction.getOutputLength();
        ipad = new byte[this.blockSizeInBytes];
        opad = new byte[this.blockSizeInBytes];
        keyXoredWithIpad = new byte[this.blockSizeInBytes];
        keyXoredWithOpad = new byte[this.blockSizeInBytes];
        Arrays.fill(ipad, (byte) 0x36);
        Arrays.fill(opad, (byte) 0x5c);
        alteredKey = new byte[blockSizeInBytes];
        initializeAlteredKey();
        initializeKeyXoredWithIpad();
        initializeKeyXoredWithOpad();
    }

    public byte[] computeMAC(String text) {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] concatenatedKeyXoredWithIpadAndText = new byte[blockSizeInBytes + textBytes.length];
        System.arraycopy(keyXoredWithIpad, 0, concatenatedKeyXoredWithIpadAndText, 0, blockSizeInBytes);
        System.arraycopy(textBytes, 0, concatenatedKeyXoredWithIpadAndText, blockSizeInBytes, textBytes.length);
        byte[] hashOfConcatenatedKeyXoredWithIpadAndText = hashFunction.computeHash(concatenatedKeyXoredWithIpadAndText);
        byte[] concatenatedKeyXoredWithOpadAndHash = new byte[blockSizeInBytes + hashOutputLengthInBytes];
        System.arraycopy(keyXoredWithOpad, 0, concatenatedKeyXoredWithOpadAndHash, 0, blockSizeInBytes);
        System.arraycopy(hashOfConcatenatedKeyXoredWithIpadAndText, 0, concatenatedKeyXoredWithOpadAndHash, blockSizeInBytes, hashOutputLengthInBytes);
        return hashFunction.computeHash(concatenatedKeyXoredWithOpadAndHash);
    }

    private void initializeAlteredKey() {
        if (key.length > blockSizeInBytes) {
            byte[] hashOfKey = hashFunction.computeHash(key);
            System.arraycopy(hashOfKey, 0, alteredKey, 0, hashOfKey.length);
        } else {
            System.arraycopy(key, 0, alteredKey, 0, key.length);
        }
    }

    private void initializeKeyXoredWithIpad() {
        for (int i = 0; i < keyXoredWithIpad.length; i++) {
            keyXoredWithIpad[i] = (byte) (alteredKey[i] ^ ipad[i]);
        }
    }

    private void initializeKeyXoredWithOpad() {
        for (int i = 0; i < keyXoredWithOpad.length; i++) {
            keyXoredWithOpad[i] = (byte) (alteredKey[i] ^ opad[i]);
        }
    }

    public void setKey(byte[] key) {
        this.key = key;
        Arrays.fill(alteredKey, (byte) 0);
        initializeAlteredKey();
        initializeKeyXoredWithIpad();
        initializeKeyXoredWithOpad();
    }
}

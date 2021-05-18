package Lab6KeyDerivation;

import Lab2HashAlgorithm.BlueMidnightWish;
import Lab2HashAlgorithm.BlueMidnightWishDigestSize;
import Lab2HashAlgorithm.HashFunction;

public class KeyDerivationSpeedTest {
    public static void speedTestForDerivedKeyWithSpecifiedLength(HashFunction hashFunction, boolean[] flags) {
        KeyDerivation keyDerivation = new KeyDerivation(hashFunction, flags);
        long start = System.currentTimeMillis();
        keyDerivation.generateDerivedKey(new byte[32], new byte[64], 2560000, new byte[32], new byte[16], new byte[16]);
        System.out.println("На выработку 320000 байт производного ключа (10000 ключей длины 256 бит) затрачено: " + (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        keyDerivation.generateDerivedKey(new byte[32], new byte[64], 167772160, new byte[32], new byte[16], new byte[16]);
        System.out.println("На выработку 20 Мб производного ключа затрачено: " + (System.currentTimeMillis() - start) + " мс");
        start = System.currentTimeMillis();
        keyDerivation.generateDerivedKey(new byte[32], new byte[64], 256000000, new byte[32], new byte[16], new byte[16]);
        System.out.println("На выработку 32000000 байт производного ключа (1000000 ключей длины 256 бит) затрачено: " + (System.currentTimeMillis() - start) + " мс");
    }

    public static void main(String[] args) {
        HashFunction hashFunction = new BlueMidnightWish(BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512);
        boolean[] flags = {false, false, true, true, true, true, true, true};
        speedTestForDerivedKeyWithSpecifiedLength(hashFunction, flags);
    }
}

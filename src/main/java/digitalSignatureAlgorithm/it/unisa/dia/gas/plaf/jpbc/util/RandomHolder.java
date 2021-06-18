package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util;

import java.security.SecureRandom;

/**
 * Created by Ilya Gazman on 2/3/2018.
 */
public class RandomHolder {
    public static final SecureRandom RANDOM;
    static {
        SecureRandom random;
        random = new SecureRandom();
        RANDOM = random;
    }
}
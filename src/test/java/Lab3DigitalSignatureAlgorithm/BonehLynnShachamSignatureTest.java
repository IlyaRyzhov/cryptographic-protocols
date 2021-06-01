package Lab3DigitalSignatureAlgorithm;

import Lab2HashAlgorithm.BlueMidnightWish;
import Lab2HashAlgorithm.BlueMidnightWishDigestSize;
import Lab3DigitalSignatureAlgorithm.meetingImplementation.bls.BlsSignatures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BonehLynnShachamSignatureTest {
    @Test
    @DisplayName("Вычисление подписи")
    void getSignatureTest() {
        byte[] key = new byte[23];
        new SecureRandom().nextBytes(key);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new Sha256());
        BlsSignatures blsSignatures = new BlsSignatures();
        byte[] message = new byte[128];
        new SecureRandom().nextBytes(message);
        assertArrayEquals(blsSignatures.sign(message, key).signature.toBytes(), bonehLynnShachamSignature.getSignature(message));
    }

    @Test
    @DisplayName("Проверка подписи")
    void verifySignatureTest() {
        byte[] key = new byte[23];
        new SecureRandom().nextBytes(key);
        byte[] message = new byte[128];
        new SecureRandom().nextBytes(message);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512));
        byte[] signature = bonehLynnShachamSignature.getSignature(message);
        assertTrue(bonehLynnShachamSignature.verifySignature(message, signature));
    }
}

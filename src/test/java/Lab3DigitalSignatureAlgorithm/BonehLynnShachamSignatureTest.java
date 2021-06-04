package Lab3DigitalSignatureAlgorithm;

import Lab2HashAlgorithm.BlueMidnightWish;
import Lab3DigitalSignatureAlgorithm.meetingImplementation.bls.BlsSignatures;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;

import static Lab2HashAlgorithm.BlueMidnightWishDigestSize.BLUE_MIDNIGHT_WISH_512;
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
        File file = new File("C:\\Users\\fvd\\Desktop\\100MB.txt");
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file))) {
            byte[] dataInFile = bufferedInputStream.readAllBytes();
            BonehLynnShachamSignature bonehLynnShachamSignatureWithBMW = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
            assertArrayEquals(bonehLynnShachamSignatureWithBMW.getSignature(file), bonehLynnShachamSignatureWithBMW.getSignature(dataInFile));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    @DisplayName("Проверка подписи")
    void verifySignatureTest() {
        byte[] key = new byte[23];
        new SecureRandom().nextBytes(key);
        byte[] message = new byte[128];
        new SecureRandom().nextBytes(message);
        BonehLynnShachamSignature bonehLynnShachamSignature = new BonehLynnShachamSignature(key, new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512));
        byte[] signature = bonehLynnShachamSignature.getSignature(message);
        assertTrue(bonehLynnShachamSignature.verifySignature(message, signature, bonehLynnShachamSignature.getPublicKey()));
        File file = new File("C:\\Users\\fvd\\Desktop\\100MB.txt");
        assertTrue(bonehLynnShachamSignature.verifySignature(file, bonehLynnShachamSignature.getSignature(file), bonehLynnShachamSignature.getPublicKey()));
    }
}

package hashAlgorithm;

import hashAlgorithm.meetingImplementation.BMW224;
import hashAlgorithm.meetingImplementation.BMW256;
import hashAlgorithm.meetingImplementation.BMW384;
import hashAlgorithm.meetingImplementation.BMW512;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static hashAlgorithm.BlueMidnightWishDigestSize.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BlueMidnightWishTest {
    @Test
    @DisplayName("Вычисление хеша с длиной выходного блока 224 бита")
    void computeHash224BitsLengthTest() {
        BlueMidnightWish blueMidnightWish = new BlueMidnightWish(BLUE_MIDNIGHT_WISH_224);
        BMW224 bmw224 = new BMW224();
        for (int i = 0; i < 100000; i++) {
            byte[] data = new byte[i];
            assertArrayEquals(bmw224.copy().digest(data), blueMidnightWish.computeHash(data), "Ошибка при i=" + i);
        }
    }

    @Test
    @DisplayName("Вычисление хеша с длиной выходного блока 256 бит")
    void computeHash256BitsLengthTest() {
        BlueMidnightWish blueMidnightWish = new BlueMidnightWish(BLUE_MIDNIGHT_WISH_256);
        BMW256 bmw256 = new BMW256();
        for (int i = 0; i < 100000; i++) {
            byte[] data = new byte[i];
            assertArrayEquals(bmw256.copy().digest(data), blueMidnightWish.computeHash(data), "Ошибка при i=" + i);
        }
    }

    @Test
    @DisplayName("Вычисление хеша с длиной выходного блока 384 бита")
    void computeHash384BitsLengthTest() {
        BlueMidnightWish blueMidnightWish = new BlueMidnightWish(BLUE_MIDNIGHT_WISH_384);
        BMW384 bmw384 = new BMW384();
        for (int i = 0; i < 100000; i++) {
            byte[] data = new byte[i];
            assertArrayEquals(bmw384.copy().digest(data), blueMidnightWish.computeHash(data), "Ошибка при i=" + i);
        }
    }

    @Test
    @DisplayName("Вычисление хеша с длиной выходного блока 512 бит")
    void computeHash512BitsLengthTest() {
        BlueMidnightWish blueMidnightWish = new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512);
        BMW512 bmw512 = new BMW512();
        for (int i = 0; i < 100000; i++) {
            byte[] data = new byte[i];
            assertArrayEquals(bmw512.copy().digest(data), blueMidnightWish.computeHash(data), "Ошибка при i=" + i);
        }
    }
}

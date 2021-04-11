package Lab2HashAlgorithm;

import Lab2HashAlgorithm.myImplementation.BlueMidnightWish;
import Lab2HashAlgorithm.myImplementation.HMAC;
import org.junit.jupiter.api.Test;

import static Lab2HashAlgorithm.myImplementation.BlueMidnightWishDigestSize.*;
import static Utils.CommonUtils.convertIntArrayToByteArray;
import static Utils.CommonUtils.convertLongArrayToByteArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

//TODO вынести data и массивы ключей в поля класса
public class HMACTest {
    @Test
    void blueMidnightWish224MacTest() {
        byte[] key = convertIntArrayToByteArray(new int[]{0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
                0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F});
        HMAC hmac = new HMAC(new BlueMidnightWish(BLUE_MIDNIGHT_WISH_224), key);
        String data = "Sample #1";
        byte[] expected = convertIntArrayToByteArray(new int[]{0xA208BC28, 0x7D297A96, 0x7C12801F, 0x12302EB7, 0xFB5511DE, 0x357D5B56, 0x77D8C050});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F, 0x40414243});
        hmac.setKey(key);
        data = "Sample #2";
        expected = convertIntArrayToByteArray(new int[]{0x525E551A, 0x5B890B00, 0xA7A99E27, 0xFF8C99AC, 0x6CD77E89, 0xE3B80300, 0x7710DF4B});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F, 0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
                0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F, 0x80818283, 0x84858687, 0x88898A8B, 0x8C8D8E8F, 0x90919293, 0x94959697, 0x98999A9B, 0x9C9D9E9F,
                0xA0A1A2A3, 0xA4A5A6A7, 0xA8A9AAAB, 0xACADAEAF, 0xB0B1B2B3});
        hmac.setKey(key);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.";
        expected = convertIntArrayToByteArray(new int[]{0xD1674B83, 0xB37830E6, 0xAF7DBCC6, 0x260E3DEC, 0xB8BB23F5, 0x6DDA2CA8, 0x28C60B87});
        assertArrayEquals(hmac.computeMAC(data), expected);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance" +
                " that a source with no knowledge of the key can present a purported MAC.";
        expected = convertIntArrayToByteArray(new int[]{0x16F9D79E, 0xF410A118, 0xDDD39839, 0x6A6A3FD0, 0xAC9816ED, 0x7110ECA9, 0x0A05430A});
        assertArrayEquals(hmac.computeMAC(data), expected);
    }

    @Test
    void blueMidnightWish256MacTest() {
        byte[] key = convertIntArrayToByteArray(new int[]{0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
                0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F});
        HMAC hmac = new HMAC(new BlueMidnightWish(BLUE_MIDNIGHT_WISH_256), key);
        String data = "Sample #1";
        byte[] expected = convertIntArrayToByteArray(new int[]{0xB5F059FD, 0x59189FA9, 0xB4C0C11C, 0x2B132C67, 0xD89CBAE1, 0xF116A2D2, 0xA1539344, 0xD8E2F938});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F, 0x40414243});
        hmac.setKey(key);
        data = "Sample #2";
        expected = convertIntArrayToByteArray(new int[]{0x7B203B54, 0x15EEF50E, 0x6E64C1C7, 0x58BD06D0, 0xED23D993, 0x1F74F713, 0xD49BD075, 0x83251FFE});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F, 0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
                0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F, 0x80818283, 0x84858687, 0x88898A8B, 0x8C8D8E8F, 0x90919293, 0x94959697, 0x98999A9B, 0x9C9D9E9F,
                0xA0A1A2A3, 0xA4A5A6A7, 0xA8A9AAAB, 0xACADAEAF, 0xB0B1B2B3});
        hmac.setKey(key);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.";
        expected = convertIntArrayToByteArray(new int[]{0x6696C409, 0x4F8D89BC, 0xEE17AF43, 0x50DC4D3E, 0x84A2E2CA, 0x1A239DE8, 0xC5B689F0, 0x7FAF6248});
        assertArrayEquals(hmac.computeMAC(data), expected);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance" +
                " that a source with no knowledge of the key can present a purported MAC.";
        expected = convertIntArrayToByteArray(new int[]{0xF5C8A1F5, 0x31FD09D1, 0xF33845E7, 0x05075A8C, 0xE5EEB29B, 0x33EFF70B, 0xAE97B750, 0xE3231383});
        assertArrayEquals(hmac.computeMAC(data), expected);
    }

    @Test
    void blueMidnightWish384MacTest() {
        byte[] key = convertIntArrayToByteArray(new int[]{0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
                0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F});
        HMAC hmac = new HMAC(new BlueMidnightWish(BLUE_MIDNIGHT_WISH_384), key);
        String data = "Sample #1";
        byte[] expected = convertLongArrayToByteArray(new long[]{0xE7BEAC8B685724D5L, 0xB625E79E007172DFL, 0x97FC85DB120DF5B7L, 0x52E618A676860EBBL, 0x73F46E70FAA0F084L, 0x937BFD6A21404913L});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F, 0x40414243});
        hmac.setKey(key);
        data = "Sample #2";
        expected = convertLongArrayToByteArray(new long[]{0x9E7DAF3407CB1BC0L, 0xCA3101F93A3D857BL, 0x44815D0C7203BC66L, 0xDE907C6C3DE7E322L, 0xE78A9072B285C97BL, 0xEED23A85521F5EE7L});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertLongArrayToByteArray(new long[]{0x5051525354555657L, 0x58595A5B5C5D5E5FL, 0x6061626364656667L, 0x68696A6B6C6D6E6FL,
                0x7071727374757677L, 0x78797A7B7C7D7E7FL, 0x8081828384858687L, 0x88898A8B8C8D8E8FL,
                0x9091929394959697L, 0x98999A9B9C9D9E9FL, 0xA0A1A2A3A4A5A6A7L, 0xA8A9AAABACADAEAFL,
                0xB0B1B2B350515253L, 0x5455565758595A5BL, 0x5C5D5E5F60616263L, 0x6465666768696A6BL,
                0x6C6D6E6F70717273L, 0x7475767778797A7BL, 0x7C7D7E7F80818283L, 0x8485868788898A8BL,
                0x8C8D8E8F90919293L, 0x9495969798999A9BL, 0x9C9D9E9FA0A1A2A3L, 0xA4A5A6A7A8A9AAABL,
                0xACADAEAFB0B1B2B3L});
        hmac.setKey(key);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.";
        expected = convertLongArrayToByteArray(new long[]{0x515079D15A09C721L, 0xC63F3E1011DC7883L, 0x7D1362753377F861L, 0xFF34F9E884B84EA0L, 0xA60ADA03AF5FC724L, 0x870CCA900EC8E3B5L});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F, 0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
                0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F, 0x80818283, 0x84858687, 0x88898A8B, 0x8C8D8E8F, 0x90919293, 0x94959697, 0x98999A9B, 0x9C9D9E9F,
                0xA0A1A2A3, 0xA4A5A6A7, 0xA8A9AAAB, 0xACADAEAF, 0xB0B1B2B3});
        hmac.setKey(key);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance" +
                " that a source with no knowledge of the key can present a purported MAC.";
        expected = convertLongArrayToByteArray(new long[]{0x9525578E38E7DD70L, 0xCB9FECB6DC72DEC0L, 0x388072FD3C63F6ECL, 0x733E26466DA7EEA2L, 0x3A5CD49C5B566D8EL, 0x730E30838F4C5563L});
        assertArrayEquals(hmac.computeMAC(data), expected);
    }


    @Test
    void blueMidnightWish512MacTest() {
        byte[] key = convertIntArrayToByteArray(new int[]{0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F, 0x10111213, 0x14151617, 0x18191A1B,
                0x1C1D1E1F, 0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F, 0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F});
        HMAC hmac = new HMAC(new BlueMidnightWish(BLUE_MIDNIGHT_WISH_512), key);
        String data = "Sample #1";
        byte[] expected = convertLongArrayToByteArray(new long[]{0x7017DB5D590A803EL, 0xCDD0E87818083D65L, 0x7BB85636ED039BAAL, 0xD3185D8CAB82E017L,
                0x2D1957757D6E5E2FL, 0x288D43E032635E8FL, 0xC4B9FAA9FD445CB1L, 0x161F7786D805529FL});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F, 0x40414243});
        hmac.setKey(key);
        data = "Sample #2";
        expected = convertLongArrayToByteArray(new long[]{0xCEF9110B1F90A240L, 0x80C8CE794FD922F8L, 0x669A1A0A74299DB9L, 0x789D9BD9CCC8BA7EL,
                0x9438BD2383F14D3CL, 0x9278FDB65C0A3FCFL, 0xCBF2EB570C085884L, 0x88F5F9AF428D8F67L});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertLongArrayToByteArray(new long[]{0x5051525354555657L, 0x58595A5B5C5D5E5FL, 0x6061626364656667L, 0x68696A6B6C6D6E6FL,
                0x7071727374757677L, 0x78797A7B7C7D7E7FL, 0x8081828384858687L, 0x88898A8B8C8D8E8FL,
                0x9091929394959697L, 0x98999A9B9C9D9E9FL, 0xA0A1A2A3A4A5A6A7L, 0xA8A9AAABACADAEAFL,
                0xB0B1B2B350515253L, 0x5455565758595A5BL, 0x5C5D5E5F60616263L, 0x6465666768696A6BL,
                0x6C6D6E6F70717273L, 0x7475767778797A7BL, 0x7C7D7E7F80818283L, 0x8485868788898A8BL,
                0x8C8D8E8F90919293L, 0x9495969798999A9BL, 0x9C9D9E9FA0A1A2A3L, 0xA4A5A6A7A8A9AAABL,
                0xACADAEAFB0B1B2B3L});
        hmac.setKey(key);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic.";
        expected = convertLongArrayToByteArray(new long[]{0x8519939233A45472L, 0x58AFB322FAABDECFL, 0xBE3F99B83CD0F760L, 0x944B3F9B9FC0CD2DL, 0xBBA98A069CC267CAL, 0x80B53D9BA6D9E89CL, 0x5A02173C661E5E71L, 0x5902D5F5B23FEA9FL});
        assertArrayEquals(hmac.computeMAC(data), expected);
        key = convertIntArrayToByteArray(new int[]{0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F, 0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
                0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F, 0x80818283, 0x84858687, 0x88898A8B, 0x8C8D8E8F, 0x90919293, 0x94959697, 0x98999A9B, 0x9C9D9E9F,
                0xA0A1A2A3, 0xA4A5A6A7, 0xA8A9AAAB, 0xACADAEAF, 0xB0B1B2B3});
        hmac.setKey(key);
        data = "The successful verification of a MAC does not completely guarantee that the accompanying message is authentic: there is a chance" +
                " that a source with no knowledge of the key can present a purported MAC.";
        expected = convertLongArrayToByteArray(new long[]{0x44FCDF6C712B75BEL, 0x3CA93EB2F98ECEABL, 0x23D7C5A3839C2D26L, 0x7CFE0A9A202E7375L, 0x6B8B30882D94725AL, 0x82D2C705B5256154L, 0x231EC14756CCF4A7L, 0x132E911CA24C1AABL});
        assertArrayEquals(hmac.computeMAC(data), expected);
    }
}
package encryptionModes.meetingImplementation;

import encryptionAlgorithm.EncryptionAlgorithm;

import static Utils.CommonUtils.*;

/**
 * Реализация алгоритма шифрования Кузнечик написана Синевым Матвеем ККСО-01-16.
 * Мною были реализованы методы интерфейса EncryptionAlgorithm.
 *
 * @author Ilya Ryzhov, Sinev Matvei
 */
public class GOST34122015 implements EncryptionAlgorithm {

    private final static int BLOCK_SIZE = 16;
    private final static byte[] l = {
            (byte) 1, (byte) 148, (byte) 32, (byte) 133, (byte) 16, (byte) 194, (byte) 192, (byte) 1,
            (byte) 251, (byte) 1, (byte) 192, (byte) 194, (byte) 16, (byte) 133, (byte) 32, (byte) 148
    };
    private final static byte[] Pi = {
            (byte) 0xFC, (byte) 0xEE, (byte) 0xDD, (byte) 0x11, (byte) 0xCF, (byte) 0x6E, (byte) 0x31, (byte) 0x16,    // 00..07
            (byte) 0xFB, (byte) 0xC4, (byte) 0xFA, (byte) 0xDA, (byte) 0x23, (byte) 0xC5, (byte) 0x04, (byte) 0x4D,    // 08..0F
            (byte) 0xE9, (byte) 0x77, (byte) 0xF0, (byte) 0xDB, (byte) 0x93, (byte) 0x2E, (byte) 0x99, (byte) 0xBA,    // 10..17
            (byte) 0x17, (byte) 0x36, (byte) 0xF1, (byte) 0xBB, (byte) 0x14, (byte) 0xCD, (byte) 0x5F, (byte) 0xC1,    // 18..1F
            (byte) 0xF9, (byte) 0x18, (byte) 0x65, (byte) 0x5A, (byte) 0xE2, (byte) 0x5C, (byte) 0xEF, (byte) 0x21,    // 20..27
            (byte) 0x81, (byte) 0x1C, (byte) 0x3C, (byte) 0x42, (byte) 0x8B, (byte) 0x01, (byte) 0x8E, (byte) 0x4F,    // 28..2F
            (byte) 0x05, (byte) 0x84, (byte) 0x02, (byte) 0xAE, (byte) 0xE3, (byte) 0x6A, (byte) 0x8F, (byte) 0xA0,    // 30..37
            (byte) 0x06, (byte) 0x0B, (byte) 0xED, (byte) 0x98, (byte) 0x7F, (byte) 0xD4, (byte) 0xD3, (byte) 0x1F,    // 38..3F
            (byte) 0xEB, (byte) 0x34, (byte) 0x2C, (byte) 0x51, (byte) 0xEA, (byte) 0xC8, (byte) 0x48, (byte) 0xAB,    // 40..47
            (byte) 0xF2, (byte) 0x2A, (byte) 0x68, (byte) 0xA2, (byte) 0xFD, (byte) 0x3A, (byte) 0xCE, (byte) 0xCC,    // 48..4F
            (byte) 0xB5, (byte) 0x70, (byte) 0x0E, (byte) 0x56, (byte) 0x08, (byte) 0x0C, (byte) 0x76, (byte) 0x12,    // 50..57
            (byte) 0xBF, (byte) 0x72, (byte) 0x13, (byte) 0x47, (byte) 0x9C, (byte) 0xB7, (byte) 0x5D, (byte) 0x87,    // 58..5F
            (byte) 0x15, (byte) 0xA1, (byte) 0x96, (byte) 0x29, (byte) 0x10, (byte) 0x7B, (byte) 0x9A, (byte) 0xC7,    // 60..67
            (byte) 0xF3, (byte) 0x91, (byte) 0x78, (byte) 0x6F, (byte) 0x9D, (byte) 0x9E, (byte) 0xB2, (byte) 0xB1,    // 68..6F
            (byte) 0x32, (byte) 0x75, (byte) 0x19, (byte) 0x3D, (byte) 0xFF, (byte) 0x35, (byte) 0x8A, (byte) 0x7E,    // 70..77
            (byte) 0x6D, (byte) 0x54, (byte) 0xC6, (byte) 0x80, (byte) 0xC3, (byte) 0xBD, (byte) 0x0D, (byte) 0x57,    // 78..7F
            (byte) 0xDF, (byte) 0xF5, (byte) 0x24, (byte) 0xA9, (byte) 0x3E, (byte) 0xA8, (byte) 0x43, (byte) 0xC9,    // 80..87
            (byte) 0xD7, (byte) 0x79, (byte) 0xD6, (byte) 0xF6, (byte) 0x7C, (byte) 0x22, (byte) 0xB9, (byte) 0x03,    // 88..8F
            (byte) 0xE0, (byte) 0x0F, (byte) 0xEC, (byte) 0xDE, (byte) 0x7A, (byte) 0x94, (byte) 0xB0, (byte) 0xBC,    // 90..97
            (byte) 0xDC, (byte) 0xE8, (byte) 0x28, (byte) 0x50, (byte) 0x4E, (byte) 0x33, (byte) 0x0A, (byte) 0x4A,    // 98..9F
            (byte) 0xA7, (byte) 0x97, (byte) 0x60, (byte) 0x73, (byte) 0x1E, (byte) 0x00, (byte) 0x62, (byte) 0x44,    // A0..A7
            (byte) 0x1A, (byte) 0xB8, (byte) 0x38, (byte) 0x82, (byte) 0x64, (byte) 0x9F, (byte) 0x26, (byte) 0x41,    // A8..AF
            (byte) 0xAD, (byte) 0x45, (byte) 0x46, (byte) 0x92, (byte) 0x27, (byte) 0x5E, (byte) 0x55, (byte) 0x2F,    // B0..B7
            (byte) 0x8C, (byte) 0xA3, (byte) 0xA5, (byte) 0x7D, (byte) 0x69, (byte) 0xD5, (byte) 0x95, (byte) 0x3B,    // B8..BF
            (byte) 0x07, (byte) 0x58, (byte) 0xB3, (byte) 0x40, (byte) 0x86, (byte) 0xAC, (byte) 0x1D, (byte) 0xF7,    // C0..C7
            (byte) 0x30, (byte) 0x37, (byte) 0x6B, (byte) 0xE4, (byte) 0x88, (byte) 0xD9, (byte) 0xE7, (byte) 0x89,    // C8..CF
            (byte) 0xE1, (byte) 0x1B, (byte) 0x83, (byte) 0x49, (byte) 0x4C, (byte) 0x3F, (byte) 0xF8, (byte) 0xFE,    // D0..D7
            (byte) 0x8D, (byte) 0x53, (byte) 0xAA, (byte) 0x90, (byte) 0xCA, (byte) 0xD8, (byte) 0x85, (byte) 0x61,    // D8..DF
            (byte) 0x20, (byte) 0x71, (byte) 0x67, (byte) 0xA4, (byte) 0x2D, (byte) 0x2B, (byte) 0x09, (byte) 0x5B,    // E0..E7
            (byte) 0xCB, (byte) 0x9B, (byte) 0x25, (byte) 0xD0, (byte) 0xBE, (byte) 0xE5, (byte) 0x6C, (byte) 0x52,    // E8..EF
            (byte) 0x59, (byte) 0xA6, (byte) 0x74, (byte) 0xD2, (byte) 0xE6, (byte) 0xF4, (byte) 0xB4, (byte) 0xC0,    // F0..F7
            (byte) 0xD1, (byte) 0x66, (byte) 0xAF, (byte) 0xC2, (byte) 0x39, (byte) 0x4B, (byte) 0x63, (byte) 0xB6
    };
    private static byte[] revPi = {
            (byte) 0xA5, (byte) 0x2D, (byte) 0x32, (byte) 0x8F, (byte) 0x0E, (byte) 0x30, (byte) 0x38, (byte) 0xC0,    // 00..07
            (byte) 0x54, (byte) 0xE6, (byte) 0x9E, (byte) 0x39, (byte) 0x55, (byte) 0x7E, (byte) 0x52, (byte) 0x91,    // 08..0F
            (byte) 0x64, (byte) 0x03, (byte) 0x57, (byte) 0x5A, (byte) 0x1C, (byte) 0x60, (byte) 0x07, (byte) 0x18,    // 10..17
            (byte) 0x21, (byte) 0x72, (byte) 0xA8, (byte) 0xD1, (byte) 0x29, (byte) 0xC6, (byte) 0xA4, (byte) 0x3F,    // 18..1F
            (byte) 0xE0, (byte) 0x27, (byte) 0x8D, (byte) 0x0C, (byte) 0x82, (byte) 0xEA, (byte) 0xAE, (byte) 0xB4,    // 20..27
            (byte) 0x9A, (byte) 0x63, (byte) 0x49, (byte) 0xE5, (byte) 0x42, (byte) 0xE4, (byte) 0x15, (byte) 0xB7,    // 28..2F
            (byte) 0xC8, (byte) 0x06, (byte) 0x70, (byte) 0x9D, (byte) 0x41, (byte) 0x75, (byte) 0x19, (byte) 0xC9,    // 30..37
            (byte) 0xAA, (byte) 0xFC, (byte) 0x4D, (byte) 0xBF, (byte) 0x2A, (byte) 0x73, (byte) 0x84, (byte) 0xD5,    // 38..3F
            (byte) 0xC3, (byte) 0xAF, (byte) 0x2B, (byte) 0x86, (byte) 0xA7, (byte) 0xB1, (byte) 0xB2, (byte) 0x5B,    // 40..47
            (byte) 0x46, (byte) 0xD3, (byte) 0x9F, (byte) 0xFD, (byte) 0xD4, (byte) 0x0F, (byte) 0x9C, (byte) 0x2F,    // 48..4F
            (byte) 0x9B, (byte) 0x43, (byte) 0xEF, (byte) 0xD9, (byte) 0x79, (byte) 0xB6, (byte) 0x53, (byte) 0x7F,    // 50..57
            (byte) 0xC1, (byte) 0xF0, (byte) 0x23, (byte) 0xE7, (byte) 0x25, (byte) 0x5E, (byte) 0xB5, (byte) 0x1E,    // 58..5F
            (byte) 0xA2, (byte) 0xDF, (byte) 0xA6, (byte) 0xFE, (byte) 0xAC, (byte) 0x22, (byte) 0xF9, (byte) 0xE2,    // 60..67
            (byte) 0x4A, (byte) 0xBC, (byte) 0x35, (byte) 0xCA, (byte) 0xEE, (byte) 0x78, (byte) 0x05, (byte) 0x6B,    // 68..6F
            (byte) 0x51, (byte) 0xE1, (byte) 0x59, (byte) 0xA3, (byte) 0xF2, (byte) 0x71, (byte) 0x56, (byte) 0x11,    // 70..77
            (byte) 0x6A, (byte) 0x89, (byte) 0x94, (byte) 0x65, (byte) 0x8C, (byte) 0xBB, (byte) 0x77, (byte) 0x3C,    // 78..7F
            (byte) 0x7B, (byte) 0x28, (byte) 0xAB, (byte) 0xD2, (byte) 0x31, (byte) 0xDE, (byte) 0xC4, (byte) 0x5F,    // 80..87
            (byte) 0xCC, (byte) 0xCF, (byte) 0x76, (byte) 0x2C, (byte) 0xB8, (byte) 0xD8, (byte) 0x2E, (byte) 0x36,    // 88..8F
            (byte) 0xDB, (byte) 0x69, (byte) 0xB3, (byte) 0x14, (byte) 0x95, (byte) 0xBE, (byte) 0x62, (byte) 0xA1,    // 90..97
            (byte) 0x3B, (byte) 0x16, (byte) 0x66, (byte) 0xE9, (byte) 0x5C, (byte) 0x6C, (byte) 0x6D, (byte) 0xAD,    // 98..9F
            (byte) 0x37, (byte) 0x61, (byte) 0x4B, (byte) 0xB9, (byte) 0xE3, (byte) 0xBA, (byte) 0xF1, (byte) 0xA0,    // A0..A7
            (byte) 0x85, (byte) 0x83, (byte) 0xDA, (byte) 0x47, (byte) 0xC5, (byte) 0xB0, (byte) 0x33, (byte) 0xFA,    // A8..AF
            (byte) 0x96, (byte) 0x6F, (byte) 0x6E, (byte) 0xC2, (byte) 0xF6, (byte) 0x50, (byte) 0xFF, (byte) 0x5D,    // B0..B7
            (byte) 0xA9, (byte) 0x8E, (byte) 0x17, (byte) 0x1B, (byte) 0x97, (byte) 0x7D, (byte) 0xEC, (byte) 0x58,    // B8..BF
            (byte) 0xF7, (byte) 0x1F, (byte) 0xFB, (byte) 0x7C, (byte) 0x09, (byte) 0x0D, (byte) 0x7A, (byte) 0x67,    // C0..C7
            (byte) 0x45, (byte) 0x87, (byte) 0xDC, (byte) 0xE8, (byte) 0x4F, (byte) 0x1D, (byte) 0x4E, (byte) 0x04,    // C8..CF
            (byte) 0xEB, (byte) 0xF8, (byte) 0xF3, (byte) 0x3E, (byte) 0x3D, (byte) 0xBD, (byte) 0x8A, (byte) 0x88,    // D0..D7
            (byte) 0xDD, (byte) 0xCD, (byte) 0x0B, (byte) 0x13, (byte) 0x98, (byte) 0x02, (byte) 0x93, (byte) 0x80,    // D8..DF
            (byte) 0x90, (byte) 0xD0, (byte) 0x24, (byte) 0x34, (byte) 0xCB, (byte) 0xED, (byte) 0xF4, (byte) 0xCE,    // E0..E7
            (byte) 0x99, (byte) 0x10, (byte) 0x44, (byte) 0x40, (byte) 0x92, (byte) 0x3A, (byte) 0x01, (byte) 0x26,    // E8..EF
            (byte) 0x12, (byte) 0x1A, (byte) 0x48, (byte) 0x68, (byte) 0xF5, (byte) 0x81, (byte) 0x8B, (byte) 0xC7,    // F0..F7
            (byte) 0xD6, (byte) 0x20, (byte) 0x0A, (byte) 0x08, (byte) 0x00, (byte) 0x4C, (byte) 0xD7, (byte) 0x74
    };

    private byte[][] key;
    private byte[] pass;
    private byte[][] constC;

    public GOST34122015(byte[] pass) {
        this.pass = pass;
    }

    private byte[][] Ffunction(byte[][] in, byte[] c) {
        byte[][] res = new byte[2][BLOCK_SIZE];
        System.arraycopy(in[0], 0, res[1], 0, BLOCK_SIZE);
        byte[] tmp = xor(in[0], c);
        tmp = STransformation(tmp);
        tmp = LTransformation(tmp);
        res[0] = xor(tmp, in[1]);
        return res;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] res = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            res[i] = (byte) (a[i] ^ b[i]);
        }
        return res;
    }

    private static byte[] STransformation(byte[] in) {
        byte[] res = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            res[i] = Pi[in[i] & 0xFF];
        }
        return res;
    }

    private static byte mulGF(byte a, byte b) {
        byte res = 0, h;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                res ^= a;
            }
            h = (byte) (a & 0x80);
            a <<= 1;
            if (h != 0) {
                a ^= 0xC3;
            }
            b >>= 1;
        }
        return res;
    }

    private static byte[] RTransformation(byte[] in) {
        byte[] res = new byte[BLOCK_SIZE];
        byte tmp = 0;
        for (int i = 0; i < 16; i++) {
            if (i < 15) {
                res[i + 1] = in[i];
            }
            tmp ^= mulGF(in[i], l[15 - i]);
        }
        res[0] = tmp;
        return res;
    }

    private static byte[] LTransformation(byte[] in) {
        byte[] res = in;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            res = RTransformation(res);
        }
        return res;
    }

    private void setKey(byte[] pass) {
        key = new byte[10][16];
        byte[][] tmp1 = new byte[2][BLOCK_SIZE];
        byte[][] tmp2 = null;
        for (int i = 0; i < 16; i++) {
            key[0][i] = pass[i];
            key[1][i] = pass[i + 16];
            tmp1[0][i] = key[0][i];
            tmp1[1][i] = key[1][i];
        }
        byte[][] c = new byte[32][BLOCK_SIZE];
        for (int i = 0; i < 32; i++) {
            c[i][15] = (byte) (i + 1);
            c[i] = LTransformation(c[i]);
        }

        for (int i = 0; i < 4; i++) {
            tmp2 = Ffunction(tmp1, c[8 * i]);
            tmp1 = Ffunction(tmp2, c[8 * i + 1]);
            tmp2 = Ffunction(tmp1, c[8 * i + 2]);
            tmp1 = Ffunction(tmp2, c[8 * i + 3]);
            tmp2 = Ffunction(tmp1, c[8 * i + 4]);
            tmp1 = Ffunction(tmp2, c[8 * i + 5]);
            tmp2 = Ffunction(tmp1, c[8 * i + 6]);
            tmp1 = Ffunction(tmp2, c[8 * i + 7]);
            System.arraycopy(tmp1[0], 0, key[2 * i + 2], 0, BLOCK_SIZE);
            System.arraycopy(tmp1[1], 0, key[2 * i + 3], 0, BLOCK_SIZE);
        }
    }

    private static String byteToStr(byte[] in) {
        String s = "";
        for (int i = 0; i < 16; i++) {
            byte b = (byte) ((in[i] >> 4) & 0x0F);
            if (b > 9) {
                s += (char) (b + 87);
            } else {
                s += (char) (b + 48);
            }
            b = (byte) (in[i] & 0x0F);
            if (b > 9) {
                s += (char) (b + 87);
            } else {
                s += (char) (b + 48);
            }
        }
        return s;
    }

    private byte[] LSXrounds(byte[] in) {
        byte[] res = in;
        for (int i = 0; i < 9; i++) {
            res = xor(key[i], res);
            res = STransformation(res);
            res = LTransformation(res);
        }
        return res;
    }

    public byte[] encrypt(byte[] data) {
        setKey(pass);
        byte[] block = new byte[BLOCK_SIZE];
        System.arraycopy(data, 0, block, 0, data.length);
        block = LSXrounds(block);
        block = xor(block, key[9]);
        return block;
    }

    private static byte[] reverseRTransformation(byte[] in) {
        byte[] res = new byte[BLOCK_SIZE];
        byte tmp = in[0];
        res[15] = in[0];
        for (int i = 0; i < 15; i++) {
            if (i < 15) {
                res[i] = in[i + 1];
            }
            tmp ^= mulGF(res[i], l[15 - i]);
        }
        res[15] = tmp;
        return res;
    }

    private static byte[] reverseLTransformation(byte[] in) {
        byte[] res = in;
        for (int i = 0; i < BLOCK_SIZE; i++) {
            res = reverseRTransformation(res);
        }
        return res;
    }

    private static byte[] reverseSTransformation(byte[] in) {
        byte[] res = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            res[i] = revPi[in[i] & 0xFF];
        }
        return res;
    }

    private byte[] reverseLSX(byte[] in) {
        byte[] res = in;
        for (int i = 8; i >= 0; i--) {
            res = reverseLTransformation(res);
            res = reverseSTransformation(res);
            res = xor(key[i], res);
        }
        return res;
    }


    public byte[] decrypt(byte[] data) {
        setKey(pass);
        byte[] block = new byte[BLOCK_SIZE];
        System.arraycopy(data, 0, block, 0, data.length);
        block = xor(block, key[9]);
        block = reverseLSX(block);
        return block;
    }

    @Override
    public byte[] encryptOneBlock(byte[] plainText) {
        return encrypt(plainText);
    }

    @Override
    public byte[] decryptOneBlock(byte[] cipherText) {
        return decrypt(cipherText);
    }

    @Override
    public int getBlockSizeInBytes() {
        return BLOCK_SIZE;
    }

    @Override
    public int getKeySizeInBytes() {
        return pass.length;
    }

    @Override
    public void setKey(long[] key) {
        pass = convertLongArrayToByteArray(key);
    }

    @Override
    public EncryptionAlgorithm getInstance() {
        byte[] pass = new byte[this.pass.length];
        System.arraycopy(this.pass, 0, pass, 0, this.pass.length);
        return new GOST34122015(pass);
    }
}

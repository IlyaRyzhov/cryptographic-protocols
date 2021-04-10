package Lab2HashAlgorithm.cryptohash.test;

import Lab2HashAlgorithm.cryptohash.BMW224;
import Lab2HashAlgorithm.cryptohash.BMW256;
import Lab2HashAlgorithm.cryptohash.BMW384;
import Lab2HashAlgorithm.cryptohash.BMW512;
//import fr.cryptohash.BMW224;

import java.util.Arrays;

public class test {
    public static void main(String[] args) {
        BMW256 bmw256 = new BMW256();
        byte[] arr = new byte[10];
        arr[0] = 'a';
        arr[1] = 'b';
        arr[2] = 'c';
        //    arr[0]=0x0c;
        //Arrays.fill(arr, (byte) 0x0C);
        Arrays.fill(arr, (byte) 0x15);
        System.out.println(Arrays.toString(bmw256.copy().digest(arr)));
        byte[] mas = bmw256.copy().digest(arr);
        for (int i = 0; i < mas.length; i++) {
            System.out.print(Integer.toHexString(mas[i] & 0xff) + " ");
        }
        System.out.println();
        //[40, 67, 85, -88, -57, -120, 16, -124, 101, -77, -24, -61, -48, -60, -94, -97, -43, -111, -21, -36, 121, 126, 40, -91, -90, 79, 28, 93, 93, 45, -43, 45]
        //[1, 96, -6, 85, 9, -101, -38, -96, 5, -20, 19, 45, -118, -19, 78, -118, -117, 62, 33, -70, 112, 13, 36, -36, 48, 68, -50, -120]
        //[12, -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 0, 0, 0, 0, 0, 0]
        BMW384 bmw384 = new BMW384();

        System.out.println(Arrays.toString(bmw384.copy().digest(arr)));
        BMW512 bmw512 = new BMW512();
        System.out.println(Arrays.toString(bmw512.copy().digest(arr)));
        byte[] mas2 = new byte[64000000];
        long start = System.currentTimeMillis();
        bmw256.copy().digest(mas2);
        System.out.println(System.currentTimeMillis() - start);
    }

}

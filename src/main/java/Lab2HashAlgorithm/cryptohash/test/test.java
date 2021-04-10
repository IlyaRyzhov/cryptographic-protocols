package Lab2HashAlgorithm.cryptohash.test;

import Lab2HashAlgorithm.cryptohash.BMW224;
import Lab2HashAlgorithm.cryptohash.BMW256;
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
            System.out.print(Integer.toHexString(mas[i]&0xff)+" ");
        }
        //[1, 96, -6, 85, 9, -101, -38, -96, 5, -20, 19, 45, -118, -19, 78, -118, -117, 62, 33, -70, 112, 13, 36, -36, 48, 68, -50, -120]
        //[12, -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 0, 0, 0, 0, 0, 0]
    }

}

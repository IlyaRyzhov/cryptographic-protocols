package Lab2HashAlgorithm.cryptohash.test;

import fr.cryptohash.BMW224;

import java.util.Arrays;

public class test {
    public static void main(String[] args) {
        BMW224 bmw224 = new BMW224();
        byte[] arr=new byte[129];
/*        arr[0]='a';
        arr[1]='b';
        arr[2]='c';*/
        arr[0]=0x0c;
        //Arrays.fill(arr, (byte) 0x0C);
        System.out.println(Arrays.toString(bmw224.copy().digest(arr)));
        //[1, 96, -6, 85, 9, -101, -38, -96, 5, -20, 19, 45, -118, -19, 78, -118, -117, 62, 33, -70, 112, 13, 36, -36, 48, 68, -50, -120]
        //[12, -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4, 0, 0, 0, 0, 0, 0]
    }

}

package digitalSignatureAlgorithm.meetingImplementation.bls.model;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Pairing;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Ilya Gazman on 2/3/2018.
 */
public enum BlsModel {
    instance;

    public final Pairing pairing;
    public final Element systemParameters;

    BlsModel(){
        pairing = PairingFactory.getPairing("pairing/parameters/a/a_181_603.properties");
        systemParameters = pairing.getG2().newElementFromBytes(
                new byte[]{21, 112, 31, 97, 41, -23, 47, 110, 99, -52, 96, -93, -99, 93, -96, 120, -120, 46, 32, 14,
                        71, -45, 3, 21, 6, -104, 67, 15, 47, -79, 38, 115, 30, -35, -117, 75, -109, 86, -116, -128,
                        -27, 48, -17, 52, 73, 31, -50, 122, -24, 73, -110, -65, -36, -74, -6, 27, 69, -96, -114, -86,
                        -91, -113, -74, -99, 25, 91, -71, -42, -60, -126, 81, 93, 47, 93, -110, -101, 17, 88, -111, 22,
                        37, -97, 32, 26, -82, 3, 43, 98, 96, 127, 74, -106, 80, -115, 13, 12, -32, 110, 52, -94,
                        -74, -44, 31, -5, -115, 34, 6, -69, 50, -87, -85, -19, -23, 117, -44, -105, 77, 105, -8, -81,
                        79, 57, 127, -98, 61, 116, -36, 81, 40, 88, -6, -98, -36, 73, 20, 12, 13, 28, -112, -13,
                        29, -88, -48, 126, -60, 4, 19, 13, 35, 51, -94, 34});
    }
}

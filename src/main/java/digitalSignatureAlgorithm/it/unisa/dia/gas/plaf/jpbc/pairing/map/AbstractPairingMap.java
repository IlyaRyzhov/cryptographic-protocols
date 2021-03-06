package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.map;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Pairing;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingPreProcessing;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Point;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.accumulator.PairingAccumulator;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.accumulator.PairingAccumulatorFactory;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public abstract class AbstractPairingMap implements PairingMap {

    private final Pairing pairing;

    protected AbstractPairingMap(Pairing pairing) {
        this.pairing = pairing;
    }


    public boolean isProductPairingSupported() {
        return false;
    }

    public Element pairing(Element[] in1, Element[] in2) {
        PairingAccumulator combiner = PairingAccumulatorFactory.getInstance().getPairingMultiplier(pairing);
        for (int i = 0; i < in1.length; i++)
            combiner.addPairing(in1[i], in2[i]);
        return combiner.awaitResult();
    }

    public int getPairingPreProcessingLengthInBytes() {
        return pairing.getG1().getLengthInBytes();
    }

    public PairingPreProcessing pairing(final Point in1) {
        return new DefaultPairingPreProcessing(pairing, in1);
    }

    public PairingPreProcessing pairing(byte[] source, int offset) {
        return new DefaultPairingPreProcessing(pairing, pairing.getG1(), source, offset);
    }


    protected final void pointToAffine(Element Vx, Element Vy, Element z, Element z2, Element e0) {
        // Vx = Vx * z^-2
        Vx.mul(e0.set(z.invert()).square());
        // Vy = Vy * z^-3
        Vy.mul(e0.mul(z));

        z.setToOne();
        z2.setToOne();
    }

}

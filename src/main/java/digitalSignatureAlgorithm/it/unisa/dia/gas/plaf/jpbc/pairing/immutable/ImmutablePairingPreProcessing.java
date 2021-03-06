package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.immutable;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingPreProcessing;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 * @since 2.0.0
 */
public class ImmutablePairingPreProcessing implements PairingPreProcessing {

    private final PairingPreProcessing pairingPreProcessing;

    ImmutablePairingPreProcessing(PairingPreProcessing pairingPreProcessing) {
        this.pairingPreProcessing = pairingPreProcessing;
    }

    public Element pairing(Element in2) {
        return pairingPreProcessing.pairing(in2).getImmutable();
    }

}

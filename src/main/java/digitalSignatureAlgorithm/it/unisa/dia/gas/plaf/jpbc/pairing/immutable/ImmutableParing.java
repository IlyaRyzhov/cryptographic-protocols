package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.immutable;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Field;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Pairing;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingPreProcessing;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 * @since 2.0.0
 */
public class ImmutableParing implements Pairing {

    private final Pairing pairing;
    private final Map<Integer, Field> fieldMap;


    public ImmutableParing(Pairing pairing) {
        this.pairing = pairing;
        this.fieldMap = new HashMap<>();
    }


    public boolean isSymmetric() {
        return pairing.isSymmetric();
    }

    public int getDegree() {
        return pairing.getDegree();
    }

    public Field getG1() {
        return getFieldAt(1);
    }

    public Field getG2() {
        return getFieldAt(2);
    }

    public Field getGT() {
        return getFieldAt(3);
    }

    public Field getZr() {
        return getFieldAt(0);
    }

    public Field getFieldAt(int index) {
        return fieldMap.computeIfAbsent(index, i -> new ImmutableField(pairing.getFieldAt(i)));
    }

    public int getFieldIndex(Field field) {
        if (field instanceof ImmutableField)
            return pairing.getFieldIndex(((ImmutableField) field).field);

        return pairing.getFieldIndex(field);
    }

    public Element pairing(Element in1, Element in2) {
        return pairing.pairing(in1, in2).getImmutable();
    }

    public boolean isProductPairingSupported() {
        return pairing.isProductPairingSupported();
    }

    public Element pairing(Element[] in1, Element[] in2) {
        return pairing.pairing(in1, in2).getImmutable();
    }

    public int getPairingPreProcessingLengthInBytes() {
        return pairing.getPairingPreProcessingLengthInBytes();
    }

    public PairingPreProcessing getPairingPreProcessingFromElement(Element in1) {
        return new ImmutablePairingPreProcessing(pairing.getPairingPreProcessingFromElement(in1));
    }

    public PairingPreProcessing getPairingPreProcessingFromBytes(byte[] source) {
        return new ImmutablePairingPreProcessing(pairing.getPairingPreProcessingFromBytes(source));
    }

    public PairingPreProcessing getPairingPreProcessingFromBytes(byte[] source, int offset) {
        return new ImmutablePairingPreProcessing(pairing.getPairingPreProcessingFromBytes(source, offset));
    }

    @Override
    public String toString() {
        return "ImmutableParing{" +
                "pairing=" + pairing +
                '}';
    }
}

package Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.a;

import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Field;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingParameters;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Point;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.quadratic.DegreeTwoExtensionQuadraticField;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import Lab3DigitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.AbstractPairing;

import java.math.BigInteger;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public class TypeAPairing extends AbstractPairing {
    private static final String NAF_MILLER_PROJECTTIVE_METHOD = "naf-miller-projective";
    private static final String MILLER_PROJECTTIVE_METHOD = "miller-projective";
    private static final String MILLER_AFFINE_METHOD = "miller-affine";

    int exp2;
    int exp1;
    int sign1;

    BigInteger r;
    private BigInteger q;
    private BigInteger h;

    BigInteger phikOnr;

    private byte[] genNoCofac;

    Field Fq;
    Field<? extends Point> Fq2;
    Field<? extends Point> Eq;


    public TypeAPairing(PairingParameters params) {
        initParams(params);
        initMap(params);
        initFields();
    }


    private void initParams(PairingParameters curveParams) {
        // validate the type
        String type = curveParams.getString("type");
        if (type == null || !"a".equalsIgnoreCase(type))
            throw new IllegalArgumentException("Type not valid. Found '" + type + "'. Expected 'a'.");

        // load params
        exp2 = curveParams.getInt("exp2");
        exp1 = curveParams.getInt("exp1");
        sign1 = curveParams.getInt("sign1");

        r = curveParams.getBigInteger("r"); // r = 2^exp2 + sign1 * 2^exp1 + sign0 * 1
        q = curveParams.getBigInteger("q"); // we work in E(F_q) (and E(F_q^2))
        h = curveParams.getBigInteger("h");  // r * h = q + 1

        genNoCofac = curveParams.getBytes("genNoCofac", null);
    }


    private void initFields() {
        // Init Zr
        Zr = initFp(r);

        // Init Fq
        Fq = initFp(q);

        // Init Eq
        Eq = initEq();

        // Init Fq2
        Fq2 = initFi();

        // k=2, hence phi_k(q) = q + 1, phikOnr = (q+1)/r
        phikOnr = h;

        // Init G1, G2, GT
        G1 = Eq;
        G2 = G1;
        GT = initGT();
    }


    private Field initFp(BigInteger order) {
        return new ZrField(order);
    }

    private Field<? extends Point> initEq() {
        // Remember the curve is: y^2 = x^3 + ax
        return new CurveField<>(
                Fq.newOneElement(),   // a
                Fq.newZeroElement(),  // b
                r,                    // order
                h,                    // cofactor  (r*h)=q+1=#E(F_q)
                genNoCofac);
    }

    private Field<? extends Point> initFi() {
        return new DegreeTwoExtensionQuadraticField<Field>(Fq);
    }

    private Field initGT() {
        return new GTFiniteField(r, pairingMap, Fq2);
    }


    private void initMap(PairingParameters curveParams) {
        String method = curveParams.getString("method", NAF_MILLER_PROJECTTIVE_METHOD);

        if (NAF_MILLER_PROJECTTIVE_METHOD.endsWith(method)) {
            pairingMap = new TypeATateNafProjectiveMillerPairingMap(this);
        } else if (MILLER_PROJECTTIVE_METHOD.equals(method))
            pairingMap = new TypeATateProjectiveMillerPairingMap(this);
        else if (MILLER_AFFINE_METHOD.equals(method))
            pairingMap = new TypeATateAffineMillerPairingMap(this);
        else
            throw new IllegalArgumentException("Pairing method not recognized. Method = " + method);
    }
}
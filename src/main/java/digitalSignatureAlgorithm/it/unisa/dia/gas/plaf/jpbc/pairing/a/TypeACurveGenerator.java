package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.a;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Field;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingParameters;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.RandomHolder;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.io.Base64;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.util.math.BigIntegerUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author Angelo De Caro (jpbclib@gmail.com)
 */
public class TypeACurveGenerator implements PairingParametersGenerator {
    private final int rbits;
    private final int qbits;
    private final boolean generateCurveFieldGen;


    private TypeACurveGenerator(int rbits, int qbits) {
        this.rbits = rbits;
        this.qbits = qbits;
        this.generateCurveFieldGen = true;
    }

    public PairingParameters generate() {
        boolean found = false;

        BigInteger q;
        BigInteger r;
        BigInteger h = null;
        int exp1, exp2;
        int sign0, sign1;

        SecureRandom random = RandomHolder.RANDOM;
        do {
            // r is picked to be a Solinas prime, that is,
            // r has the form 2a +- 2b +- 1 for some integers 0 < b < a.
            r = BigInteger.ZERO;

            if (random.nextInt(Integer.MAX_VALUE) % 2 != 0) {
                exp2 = rbits - 1;
                sign1 = 1;
            } else {
                exp2 = rbits;
                sign1 = -1;
            }
            r = r.setBit(exp2);

            q = BigInteger.ZERO;
            exp1 = (random.nextInt(Integer.MAX_VALUE) % (exp2 - 1)) + 1;
            q = q.setBit(exp1);

            if (sign1 > 0) {
                r = r.add(q);
            } else {
                r = r.subtract(q);
            }

            if (random.nextInt(Integer.MAX_VALUE) % 2 != 0) {
                sign0 = 1;
                r = r.add(BigInteger.ONE);
            } else {
                sign0 = -1;
                r = r.subtract(BigInteger.ONE);
            }

            if (!r.isProbablePrime(10))
                continue;

            for (int i = 0; i < 10; i++) {
                q = BigInteger.ZERO;
                int bit = qbits - rbits - 4 + 1;
                if (bit < 3)
                    bit = 3;
                q = q.setBit(bit);

                // we randomly generate h where where h is a multiple of four and sufficiently large to
                // guarantee (hr)^2 is big enough to resist finite field attacks.
                // If h is constrained to be a multiple of three as well, then cube roots are extremely easy to
                // compute in Fq: for all x \in Fq we see x^(-(q-2)/3) is the cube root of x,
                h = BigIntegerUtils.getRandom(q).multiply(BigIntegerUtils.TWELVE);

                // Next it is checked that q = hr ?1 is prime, if it is the case we have finished.
                // Also, we choose q = -1 mod 12 so F_q2 can be implemented as F_q[i] (where i = sqrt(-1)).
                // Look at the class DegreeTwoExtensionQuadraticField and DegreeTwoExtensionQuadraticElement
                q = h.multiply(r).subtract(BigInteger.ONE);

                if (q.isProbablePrime(10)) {
                    found = true;
                    break;
                }
            }
        } while (!found);

        PropertiesParameters params = new PropertiesParameters();
        params.put("type", "pairing/parameters/a");
        params.put("q", q.toString());
        params.put("r", r.toString());
        params.put("h", h.toString());
        params.put("exp1", String.valueOf(exp1));
        params.put("exp2", String.valueOf(exp2));
        params.put("sign0", String.valueOf(sign0));
        params.put("sign1", String.valueOf(sign1));

        if (generateCurveFieldGen) {
            Field Fq = new ZrField(random, q);
            CurveField curveField = new CurveField<>(Fq.newOneElement(), Fq.newZeroElement(), r, h);
            params.put("genNoCofac", Base64.encodeBytes(curveField.getGenNoCofac().toBytes()));
        }

        return params;
    }

    public static void main(String[] args) {
        if (args.length < 2)
            throw new IllegalArgumentException("Too few arguments. Usage <rbits> <qbits>");

        if (args.length > 2)
            throw new IllegalArgumentException("Too many arguments. Usage <rbits> <qbits>");

        Integer rBits = Integer.parseInt(args[0]);
        Integer qBits = Integer.parseInt(args[1]);

        TypeACurveGenerator generator = new TypeACurveGenerator(rBits, qBits);
        PairingParameters curveParams = generator.generate();

        System.out.println(curveParams.toString(" "));
    }

}

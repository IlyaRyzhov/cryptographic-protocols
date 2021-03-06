package digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.g;

import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Element;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Point;
import digitalSignatureAlgorithm.it.unisa.dia.gas.jpbc.Polynomial;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteElement;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.gt.GTFiniteField;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.field.poly.PolyModElement;
import digitalSignatureAlgorithm.it.unisa.dia.gas.plaf.jpbc.pairing.map.AbstractMillerPairingMap;

import java.util.List;

public class TypeGTateAffineNoDenomMillerPairingMap extends AbstractMillerPairingMap<Polynomial> {
    private final TypeGPairing pairing;


    public TypeGTateAffineNoDenomMillerPairingMap(TypeGPairing pairing) {
        super(pairing);

        this.pairing = pairing;
    }


    public Element pairing(Point in1, Point in2) {
        // map from twist: (x, y) --> (v^-1 x, v^-(3/2) y)
        // where v is the quadratic non-residue used to construct the twist
        Polynomial Qx = (Polynomial) in2.getX().duplicate().mul(pairing.nqrInverse);
        // v^-3/2 = v^-2 * v^1/2
        Polynomial Qy = (Polynomial) in2.getY().duplicate().mul(pairing.nqrInverseSquare);

        return new GTFiniteElement(this, (GTFiniteField) pairing.getGT(), tatePow(pairing(in1, Qx, Qy)));
    }

    public void finalPow(Element element) {
        element.set(tatePow(element));
    }


    private Element tatePow(Element element) {
        Point<Polynomial> e0, e3;
        PolyModElement e2;

        e0 = pairing.Fqk.newElement();
        e2 = pairing.Fqd.newElement();
        e3 = pairing.Fqk.newElement();

        Polynomial e0re = e0.getX();
        Polynomial e0im = e0.getY();

        Element e0re0 = e0re.getCoefficient(0);
        Element e0im0 = e0im.getCoefficient(0);

        Point<Polynomial> in = (Point<Polynomial>) element;
        List<Element> inre = in.getX().getCoefficients();
        List<Element> inmi = in.getY().getCoefficients();

        qPower(1, e2, e0re, e0im, e0re0, e0im0, inre, inmi);
        e3.set(e0);
        e0re.set(in.getX());
        e0im.set(in.getY()).negate();
        e3.mul(e0);
        qPower(-1, e2, e0re, e0im, e0re0, e0im0, inre, inmi);
        e0.mul(in);
        e0.invert();
        in.set(e3).mul(e0);
        e0.set(in);

        return lucasEven(e0, pairing.phikOnr);
    }

    private void qPower(int sign, PolyModElement e2,
                        Element e0re, Element e0im, Element e0re0, Element e0im0,
                        List<Element> inre, List<Element> inim) {
        e2.set(pairing.xPowq).polymodConstMul(inre.get(1));
        e0re.set(e2);
        e2.set(pairing.xPowq2).polymodConstMul(inre.get(2));
        e0re.add(e2);
        e2.set(pairing.xPowq3).polymodConstMul(inre.get(3));
        e0re.add(e2);
        e2.set(pairing.xPowq4).polymodConstMul(inre.get(4));
        e0re.add(e2);
        e0re0.add(inre.get(0));

        if (sign > 0) {
            e2.set(pairing.xPowq).polymodConstMul(inim.get(1));
            e0im.set(e2);
            e2.set(pairing.xPowq2).polymodConstMul(inim.get(2));
            e0im.add(e2);
            e2.set(pairing.xPowq3).polymodConstMul(inim.get(3));
            e0im.add(e2);
            e2.set(pairing.xPowq4).polymodConstMul(inim.get(4));
            e0im.add(e2);

            e0im0.add(inim.get(0));
        } else {
            e2.set(pairing.xPowq).polymodConstMul(inim.get(1));
            e0im.set(e2).negate();
            e2.set(pairing.xPowq2).polymodConstMul(inim.get(2));
            e0im.sub(e2);
            e2.set(pairing.xPowq3).polymodConstMul(inim.get(3));
            e0im.sub(e2);
            e2.set(pairing.xPowq4).polymodConstMul(inim.get(4));
            e0im.sub(e2);
            e0im0.sub(inim.get(0));
        }
    }


    private Element pairing(Point P, Polynomial Qx, Polynomial Qy) {
        Element Px = P.getX();
        Element Py = P.getY();

        Point Z = (Point) P.duplicate();
        Element Zx = Z.getX();
        Element Zy = Z.getY();

        Element a = Px.getField().newElement();
        Element b = a.duplicate();
        Element c = a.duplicate();
        Element cca = ((CurveField) P.getField()).getA();
        Element temp = a.duplicate();

        Point<Polynomial> f0 = pairing.Fqk.newElement();
        Element f = pairing.Fqk.newOneElement();

        for (int m = pairing.r.bitLength() - 2; m > 0; m--) {
            tangentStep(f0, a, b, c, Zx, Zy, cca, temp, Qx, Qy, f);
            Z.twice();

            if (pairing.r.testBit(m)) {
                lineStep(f0, a, b, c, Zx, Zy, Px, Py, temp, Qx, Qy, f);
                Z.add(P);
            }

            f.square();
        }
        tangentStep(f0, a, b, c, Zx, Zy, cca, temp, Qx, Qy, f);

        return f;
    }

    protected void millerStep(Point<Polynomial> out, Element a, Element b, Element c, Polynomial Qx, Polynomial Qy) {
        // a, b, c are in Fq
        // point Q is (Qx, Qy * sqrt(nqr)) where nqr is used to construct
        // the quadratic field extension Fqk of Fqd

        Polynomial rePart = out.getX();
        Polynomial imPart = out.getY();

        int i;
        //int d = rePart.getField().getN();
        int d = rePart.getDegree();
        for (i = 0; i < d; i++) {
            rePart.getCoefficient(i).set(Qx.getCoefficient(i)).mul(a);
            imPart.getCoefficient(i).set(Qy.getCoefficient(i)).mul(b);
        }

        rePart.getCoefficient(0).add(c);
    }

}
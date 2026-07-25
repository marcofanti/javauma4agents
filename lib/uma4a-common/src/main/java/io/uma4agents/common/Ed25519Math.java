package io.uma4agents.common;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * RFC 8032 §5.1.5 Ed25519 public-key derivation from a 32-byte seed, in plain
 * {@link BigInteger} arithmetic. Only used at key-load time (never per-request),
 * so affine double-and-add with Fermat inversion is fast enough. Verified
 * against JDK-generated keypairs in tests.
 */
final class Ed25519Math {

    private static final BigInteger P =
            BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D = BigInteger.valueOf(-121665)
            .multiply(inv(BigInteger.valueOf(121666))).mod(P);
    private static final BigInteger BY =
            BigInteger.valueOf(4).multiply(inv(BigInteger.valueOf(5))).mod(P);
    private static final BigInteger BX = recoverX(BY, 0);

    private Ed25519Math() {}

    static byte[] publicKeyFromSeed(byte[] seed) {
        byte[] h = sha512(seed);
        byte[] scalarBytes = new byte[32];
        System.arraycopy(h, 0, scalarBytes, 0, 32);
        scalarBytes[0] &= (byte) 248;
        scalarBytes[31] &= 127;
        scalarBytes[31] |= 64;
        BigInteger a = fromLittleEndian(scalarBytes);

        BigInteger[] point = scalarMultBase(a);
        return encodePoint(point[0], point[1]);
    }

    private static BigInteger[] scalarMultBase(BigInteger scalar) {
        BigInteger[] q = {BigInteger.ZERO, BigInteger.ONE};
        BigInteger[] p = {BX, BY};
        for (int i = 0; i < scalar.bitLength(); i++) {
            if (scalar.testBit(i)) {
                q = add(q, p);
            }
            p = add(p, p);
        }
        return q;
    }

    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger x1 = p[0];
        BigInteger y1 = p[1];
        BigInteger x2 = q[0];
        BigInteger y2 = q[1];
        BigInteger prod = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2).mod(P);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1))
                .multiply(inv(BigInteger.ONE.add(prod))).mod(P);
        BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2))
                .multiply(inv(BigInteger.ONE.subtract(prod))).mod(P);
        return new BigInteger[] {x3, y3};
    }

    private static BigInteger recoverX(BigInteger y, int signBit) {
        BigInteger yy = y.multiply(y).mod(P);
        BigInteger u = yy.subtract(BigInteger.ONE).mod(P);
        BigInteger v = D.multiply(yy).add(BigInteger.ONE).mod(P);
        BigInteger xx = u.multiply(inv(v)).mod(P);
        BigInteger x = xx.modPow(P.add(BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P);
        if (!x.multiply(x).mod(P).equals(xx)) {
            BigInteger i = BigInteger.TWO.modPow(
                    P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P);
            x = x.multiply(i).mod(P);
        }
        if (x.testBit(0) != (signBit == 1)) {
            x = P.subtract(x);
        }
        return x;
    }

    private static byte[] encodePoint(BigInteger x, BigInteger y) {
        byte[] out = toLittleEndian(y);
        if (x.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    private static BigInteger inv(BigInteger v) {
        return v.modPow(P.subtract(BigInteger.TWO), P);
    }

    private static BigInteger fromLittleEndian(byte[] bytes) {
        byte[] be = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            be[i] = bytes[bytes.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    private static byte[] toLittleEndian(BigInteger v) {
        byte[] be = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(be.length, 32);
        for (int i = 0; i < len; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static byte[] sha512(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 unavailable", e);
        }
    }
}

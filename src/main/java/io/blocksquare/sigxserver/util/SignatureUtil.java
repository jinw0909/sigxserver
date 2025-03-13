package io.blocksquare.sigxserver.util;

import lombok.extern.slf4j.Slf4j;
import org.sol4k.Base58;
import org.sol4k.PublicKey;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

@Slf4j
public class SignatureUtil {

    public static String recoverAddress(String message, String signatureHex) throws Exception {
        //Convert the message to the Ethereum signed message hash
        byte[] messageHash = Sign.getEthereumMessageHash(message.getBytes(StandardCharsets.UTF_8));
        System.out.println("hashed challenge: " + Numeric.toHexString(messageHash));

        //Parse signature: 65 bytes (r[32] + s[32] + v[1]
        byte[] signatureBytes = Numeric.hexStringToByteArray(signatureHex);
        if (signatureBytes.length != 65) {
            throw new IllegalArgumentException("Invalid signature length");
        }

        byte v = signatureBytes[64];
        if (v < 27) {
            v += 27;
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signatureBytes, 0, r, 0, 32);
        System.arraycopy(signatureBytes, 32, s, 0, 32);
        Sign.SignatureData signatureData = new Sign.SignatureData(v, r, s);
        System.out.println("v: " + Numeric.toHexString(signatureData.getV()));
        System.out.println("r: " + Numeric.toHexString(signatureData.getR()));
        System.out.println("s: " + Numeric.toHexString(signatureData.getS()));

        BigInteger publicKeyRecovered = Sign.signedMessageHashToKey(messageHash, signatureData);
        log.info("publicKeyRecoverd(BigInteger):  {}", publicKeyRecovered);
        String addressRecovered = "0x" + Keys.getAddress(publicKeyRecovered);
        return addressRecovered;
    }

    public static boolean recoverPhantom(String message, String walletAddress, String signature) {
        byte[] messageBytes = message.getBytes();
        PublicKey publicKey = new PublicKey(walletAddress);
        byte[] signatureBytes = Base58.decode(signature);
        return publicKey.verify(signatureBytes, messageBytes);
    }
}

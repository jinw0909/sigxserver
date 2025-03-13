package io.blocksquare.sigxserver.security;

import io.blocksquare.sigxserver.util.SignatureUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

@Component
@Slf4j
public class WalletAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private ChallangeService challangeService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // Expect the principal to be a Map containing walletName, publicKey, challenge, and signature.
        Object principalObj = authentication.getPrincipal();
        if (!(principalObj instanceof Map)) {
            return null;
        }

        Map<?, ?> principalMap = (Map<?, ?>) principalObj;
        String walletName = (String) principalMap.get("walletName");
        String publicKey = (String) principalMap.get("publicKey");
        String challenge = (String) principalMap.get("challenge");
        String signature = (String) principalMap.get("signature");

        log.info("parameters sent[ walletName: {}, publicKey: {}, challenge: {}, signature: {} ]", walletName, publicKey, challenge, signature);
        //Verify the challange is valid.
        if (!challangeService.verifyChallenge(publicKey, challenge)) {
            throw new RuntimeException("Invalid or expired challenge");
        }

        try {
            //Recover the address from the signature
            String recoveredAddress = SignatureUtil.recoverAddress(challenge, signature);
            //Compare recovered address with provided publicKey (case insensitive).
            log.info("recovered address = {}", recoveredAddress);
            if (!recoveredAddress.equalsIgnoreCase(publicKey)) {
                throw new RuntimeException("Signature verification failed");
            }
        } catch (Exception e) {
            throw new RuntimeException("Error during signature verification", e);
        }
        // Remove the challenge after successful verification
        challangeService.removeChallenge(publicKey);

        // Create user details and mark authentication as successful.
        WalletUserDetails userDetails = new WalletUserDetails(walletName, publicKey);
        return new WalletAuthenticationToken(userDetails, null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return WalletAuthenticationToken.class.isAssignableFrom(authentication);
    }
}

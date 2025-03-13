package io.blocksquare.sigxserver.security;

import io.blocksquare.sigxserver.util.SignatureUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class PhantomAuthenticationProvider implements AuthenticationProvider {

   private final ChallangeService challangeService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        //Expect the principal to be a Map containing walletName, publicKey, challenge, and signature
        Object principalObj = authentication.getPrincipal();
        if (!(principalObj instanceof Map)) {
            return null;
        }

        Map<?, ?> principalMap = (Map<?, ?>) principalObj;
        String walletName = (String) principalMap.get("walletName");
        String publicKey = (String) principalMap.get("publicKey");
        String challenge = (String) principalMap.get("challenge");
        String signature = (String) principalMap.get("signature");

        log.info("parameters sent[ walletName: {}, publicKey: {}, challenge: {}, signature: {}]", walletName, publicKey, challenge, signature);
        //Verify the challenge is valid.
        if (!challangeService.verifyChallenge(publicKey, challenge)) {
            throw new RuntimeException("Invalid or expired challenge");
        }

        try {
            boolean recoveredResult = SignatureUtil.recoverPhantom(challenge, publicKey, signature);
            log.info("recovery success ? = {}", recoveredResult);
            if (!recoveredResult) {
                throw new RuntimeException("Signature verification failed");
            }
        } catch (Exception e) {
            throw new RuntimeException("Error during phantom signature verification");
        }
        //Remove the challenge after successful verification
        challangeService.removeChallenge(publicKey);

        WalletUserDetails userDetails = new WalletUserDetails(walletName, publicKey);
        return new PhantomAuthenticationToken(userDetails, null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PhantomAuthenticationToken.class.isAssignableFrom(authentication);
    }
}


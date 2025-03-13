package io.blocksquare.sigxserver.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import java.io.IOException;
import java.util.Map;

public class WalletAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public WalletAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
        super(defaultFilterProcessesUrl);
        setAuthenticationManager(authenticationManager);
    }
//
//    public WalletAuthenticationFilter(String defaultFilterProcessesUrl, AuthenticationManager authenticationManager) {
//        super(defaultFilterProcessesUrl);
//        setAuthenticationManager(authenticationManager);
//    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // Parse JSON payload.
        Map<String, String> authRequest = objectMapper.readValue(request.getInputStream(), Map.class);
        // Expected keys: walletName, publicKey, challenge, signature.
        return getAuthenticationManager().authenticate(new WalletAuthenticationToken(authRequest, null));
    }
}

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

public class PhantomAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public PhantomAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    public PhantomAuthenticationFilter(String defaultFilterProcessUrl, AuthenticationManager authenticationManager) {
        super(defaultFilterProcessUrl);
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        //Parse JSON payload
        Map<String, String> authRequest = objectMapper.readValue(request.getInputStream(), Map.class);
        //Expected keys: walletName, publicKey, challenge, signature
        return getAuthenticationManager().authenticate(new PhantomAuthenticationToken(authRequest, null));
    }
}

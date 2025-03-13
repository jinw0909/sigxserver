package io.blocksquare.sigxserver.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.blocksquare.sigxserver.entity.WalletUser;
import io.blocksquare.sigxserver.repository.WalletUserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class WalletAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final WalletUserRepository walletUserRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        WalletUserDetails userDetails = (WalletUserDetails) authentication.getPrincipal();

        //String role = authentication.getAuthorities().stream().findFirst().map(GrantedAuthority::getAuthority).orElse("ROLE_USER");

        WalletUser walletUser = walletUserRepository.findByPublicKey(userDetails.getPublicKey());

        try {
            if (walletUser == null) {
                walletUser = new WalletUser();
                walletUser.setWalletName(userDetails.getWalletName());
                walletUser.setPublicKey(userDetails.getPublicKey());
                walletUser.setRole("ROLE_USER");
                walletUser.setCreatedAt(LocalDateTime.now());
            }
            //Always update updatedAt
            walletUser.setUpdatedAt(LocalDateTime.now());

            // Save (insert or update)
            walletUserRepository.save(walletUser);
        } catch (Exception e) {
            // Log the exception and possibly notify monitoring systems
            // Optionally, set default values or flag an error in your response payload
            // For instance, you might want to leave role and lastLogin as null or with a default
            // value if saving to the DB fails.
            // logger.error("Error updating wallet user in DB", e);
            walletUser = null;
        }

        Map<String, Object> authResponse = Map.of(
                "walletName", userDetails.getWalletName(),
                "publicKey", userDetails.getPublicKey(),
                "authenticated", true,
                "role", walletUser != null ? walletUser.getRole() : "ROLE_USER",
                "lastLogin", walletUser != null ? walletUser.getUpdatedAt() : LocalDateTime.now()
        );

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
    }
}

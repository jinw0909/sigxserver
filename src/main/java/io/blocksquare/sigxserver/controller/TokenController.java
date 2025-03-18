package io.blocksquare.sigxserver.controller;

import io.blocksquare.sigxserver.entity.WalletUser;
import io.blocksquare.sigxserver.repository.WalletUserRepository;
import io.blocksquare.sigxserver.security.WalletUserDetails;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@Slf4j
public class TokenController {

    private final WalletUserRepository walletUserRepository;

    @GetMapping("/tokenamount")
    public BigDecimal getTokenAmount(HttpServletRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.isAuthenticated()) {
            throw new RuntimeException("User is not authenticated");
        }

        Object principal = authentication.getPrincipal();
        String publicKey = ((WalletUserDetails) principal).getPublicKey();

        // Get the current HTTP session without creating a new one if it doesn't exist
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.error("No HTTP session found.");
            throw new RuntimeException("No HTTP session available");
        }

        // Retrieve the session ID from the current session
        String sessionId = session.getId();
        log.info("Session ID from HttpSession: {}", sessionId);

        // Retrieve the JSESSIONID from the cookies
        String jsessionIdFromCookie = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("JSESSIONID".equals(cookie.getName())) {
                    jsessionIdFromCookie = cookie.getValue();
                    break;
                }
            }
        }

        if (jsessionIdFromCookie == null) {
            log.error("JSESSIONID cookie not found.");
            throw new RuntimeException("JSESSIONID cookie missing");
        }

        log.info("JSESSIONID from cookie: {}", jsessionIdFromCookie);

        // Compare the session ID from the session with the JSESSIONID from the cookie
        if (!sessionId.equals(jsessionIdFromCookie)) {
            log.error("Session ID mismatch: session.getId()={} vs JSESSIONID cookie={}", sessionId, jsessionIdFromCookie);
            throw new RuntimeException("Session ID mismatch");
        }

        // Continue with your business logic.
        WalletUser walletUser = walletUserRepository.findByPublicKey(publicKey);
        if (walletUser == null) {
            log.error("WalletUser not found for publicKey: {}", publicKey);
            throw new RuntimeException("WalletUser not found");
        }

        BigDecimal sigxAmount = walletUser.getSigx();
        log.info("SIGX amount for user {}: {}", publicKey, sigxAmount);
        return sigxAmount;
    }
}

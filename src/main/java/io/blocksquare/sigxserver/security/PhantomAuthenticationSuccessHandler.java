package io.blocksquare.sigxserver.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.blocksquare.sigxserver.entity.WalletUser;
import io.blocksquare.sigxserver.repository.WalletUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class PhantomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final WalletUserRepository walletUserRepository;

    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

//        HttpSession session = request.getSession(true);
//        Optionally, store the security context in the session if needed
//        session.setAttribute("SPRING_SECURITY_CONTEXT", request.getAttribute("SPRING_SECURITY_CONTEXT"));
        SecurityContext securityContext = this.securityContextHolderStrategy.getContext();
        securityContext.setAuthentication(authentication);
        this.securityContextHolderStrategy.setContext(securityContext);
        this.securityContextRepository.saveContext(securityContext, request, response);
        //6D775B42EFA1126E0FCA0D2C59AC9350
        WalletUserDetails userDetails = (WalletUserDetails) authentication.getPrincipal();
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

            //Fetch token balance from Solana RPC
            BigDecimal tokenBalance = fetchTokenBalance(userDetails.getPublicKey());
            //Save the token balance in the 'sigx' field (converted to flaot, or consider using BigDecimal)
            walletUser.setSigx(tokenBalance);

            //Save (insert or update)
            walletUserRepository.save(walletUser);

        } catch (Exception e) {
            walletUser = null;
        }

        Map<String, Object> authResponse = Map.of(
                "walletName", userDetails.getWalletName(),
                "publicKey", userDetails.getPublicKey(),
                "authenticated", true,
                "role", walletUser != null ? walletUser.getRole() : "ROLE_USER",
                "lastLogin", walletUser != null ? walletUser.getUpdatedAt() : LocalDateTime.now(),
                "sigx", walletUser != null ? walletUser.getSigx() : 0
        );

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write(objectMapper.writeValueAsString(authResponse));
    }

    /**
     * Calls the Solana RPC endpoint to fetch token balance.
     * This example calls the "getParsedTokenAccountsByOwner" method
     * for a specific token mint and sums the uiAmount from each account.
     *
     * @param walletPublicKey The wallet public key as a string.
     * @return The token balance as BigDecimal.
     */
    private BigDecimal fetchTokenBalance(String walletPublicKey) {
        try {
            // RPC endpoint and token mint address
            String rpcUrl = "https://winter-evocative-silence.solana-mainnet.quiknode.pro/04a5e639b0bd9ceeec758a6140dc1aa1b08f62bd";
            String tokenMint = "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN";

            // Build the JSON-RPC payload using "getTokenAccountsByOwner" with "jsonParsed" encoding.
            Map<String, Object> payload = Map.of(
                    "jsonrpc", "2.0",
                    "id", 1,
                    "method", "getTokenAccountsByOwner",
                    "params", List.of(
                            walletPublicKey,
                            Map.of("mint", tokenMint),
                            Map.of("encoding", "jsonParsed")
                    )
            );

            // Create an HttpClient instance
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create(rpcUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                    .build();

            HttpResponse<String> httpResponse = client.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            if (httpResponse.statusCode() == 200) {
                // Log the entire JSON response for debugging
                String responseBody = httpResponse.body();
                System.out.println("RPC Response: " + responseBody);

                JsonNode root = objectMapper.readTree(responseBody);
                JsonNode result = root.path("result");
                JsonNode value = result.path("value");
                BigDecimal tokenBalance = BigDecimal.ZERO;
                if (value.isArray()) {
                    for (JsonNode accountNode : value) {
                        // Navigate to the uiAmount field: account.data.parsed.info.tokenAmount.uiAmount
                        JsonNode uiAmountNode = accountNode.path("account")
                                .path("data")
                                .path("parsed")
                                .path("info")
                                .path("tokenAmount")
                                .path("uiAmount");
                        if (!uiAmountNode.isMissingNode() && uiAmountNode.isNumber()) {
                            tokenBalance = tokenBalance.add(new BigDecimal(uiAmountNode.asText()));
                        }
                    }
                }
                System.out.println("Parsed tokenBalance: " + tokenBalance);
                return tokenBalance;
            } else {
                System.err.println("Non-200 status: " + httpResponse.statusCode());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return BigDecimal.ZERO;
    }


}

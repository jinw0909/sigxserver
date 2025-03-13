package io.blocksquare.sigxserver.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final WalletAuthenticationProvider walletAuthenticationProvider;
//    private final PhantomAuthenticationProvider phantomAuthenticationProvider;

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> myAuthenticationProviders) throws Exception {
        return new ProviderManager(myAuthenticationProviders);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager, WalletAuthenticationSuccessHandler walletAuthenticationSuccessHandler) throws Exception {
//        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();
        // Retrieve the fully built shared AuthenticationManager from HttpSecurity
        //AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        // Create and configure the custom authentication filter
        WalletAuthenticationFilter walletFilter = new WalletAuthenticationFilter("/auth/wallet", authenticationManager);
        walletFilter.setAuthenticationSuccessHandler(walletAuthenticationSuccessHandler);
        PhantomAuthenticationFilter phantomFilter = new PhantomAuthenticationFilter("/auth/phantom", authenticationManager);
        phantomFilter.setAuthenticationSuccessHandler(walletAuthenticationSuccessHandler);

        http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable()) // Disable CSRF for this example; adjust for production as needed.
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation().newSession()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                ) // Enables stateful session management.
//                .authenticationProvider(walletAuthenticationProvider)
//                .authenticationProvider(phantomAuthenticationProvider)
                // Insert the custom filter before UsernamePasswordAuthenticationFilter
                .addFilterBefore(walletFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(phantomFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/auth/wallet", "/auth/challenge", "/auth/phantom").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }


}

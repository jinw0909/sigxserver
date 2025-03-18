package io.blocksquare.sigxserver.security;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HeaderWriterLogoutHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.util.List;

import static org.springframework.security.web.header.writers.ClearSiteDataHeaderWriter.Directive.COOKIES;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final WalletAuthenticationProvider walletAuthenticationProvider;
    private final PhantomAuthenticationProvider phantomAuthenticationProvider;

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public AuthenticationManager authenticationManager(List<AuthenticationProvider> myAuthenticationProviders) throws Exception {
        return new ProviderManager(myAuthenticationProviders);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationManager authenticationManager, WalletAuthenticationSuccessHandler walletAuthenticationSuccessHandler, PhantomAuthenticationSuccessHandler phantomAuthenticationSuccessHandler) throws Exception {
//        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

        // Create and configure the custom authentication filter
        WalletAuthenticationFilter walletFilter = new WalletAuthenticationFilter("/auth/wallet", authenticationManager);
        walletFilter.setAuthenticationSuccessHandler(walletAuthenticationSuccessHandler);
        PhantomAuthenticationFilter phantomFilter = new PhantomAuthenticationFilter("/auth/phantom", authenticationManager);
        phantomFilter.setAuthenticationSuccessHandler(phantomAuthenticationSuccessHandler);

        http
                .cors(Customizer.withDefaults())// Disable CSRF for this example; adjust for production as needed.
                    .csrf(AbstractHttpConfigurer::disable)
                    .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .sessionFixation().newSession()
                        .maximumSessions(1)
                        .maxSessionsPreventsLogin(false)
                )
                .logout((logout) -> logout
                .addLogoutHandler(new HeaderWriterLogoutHandler(new ClearSiteDataHeaderWriter(COOKIES)))
                        .logoutSuccessUrl("/"))
                // Enables stateful session management.
//                .authenticationProvider(phantomAuthenticationProvider)
//                .authenticationProvider(walletAuthenticationProvider)
                // Insert the custom filter before UsernamePasswordAuthenticationFilter
                .addFilterBefore(walletFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(phantomFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/auth/wallet", "/auth/challenge", "/auth/phantom", "/sendwalletinfo", "/error", "/favicon.ico").permitAll()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
                                .anyRequest().authenticated()
                )
                .securityContext((securityContext) -> securityContext
                .securityContextRepository(new HttpSessionSecurityContextRepository())
        );

        return http.build();
    }

}

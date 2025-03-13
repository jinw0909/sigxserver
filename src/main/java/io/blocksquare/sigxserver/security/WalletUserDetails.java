package io.blocksquare.sigxserver.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class WalletUserDetails implements UserDetails {

    private final String walletName;
    private final String publicKey;

    public WalletUserDetails(String walletName, String publicKey) {
        this.walletName = walletName;
        this.publicKey = publicKey;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> "ROLE_USER");
    }

    @Override
    public String getPassword() {
        return null; // Not applicable
    }

    @Override
    public String getUsername() {
        return null;
    }

    public String getWalletName() {
        return walletName;
    }

    public String getPublicKey() {
        return publicKey;
    }

    @Override
    public boolean isAccountNonExpired() {
        //return UserDetails.super.isAccountNonExpired();
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        //return UserDetails.super.isAccountNonLocked();
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        //return UserDetails.super.isCredentialsNonExpired();
        return true;
    }

    @Override
    public boolean isEnabled() {
        //return UserDetails.super.isEnabled();
        return true;
    }
}

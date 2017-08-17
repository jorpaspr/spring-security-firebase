package io.github.awaters1.security.model;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
public class FirebaseUserDetails implements UserDetails {

    private static final long serialVersionUID = 1L;

    private final boolean enabled = true;
    private final boolean credentialsNonExpired = true;
    private final boolean accountNonLocked = true;
    private final boolean accountNonExpired = true;
    private final String password = null;
    private final String username;
    private final String id;

    public FirebaseUserDetails(String username, String id) {
        this.username = username;
        this.id = id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return false;
    }

    @Override
    public boolean isAccountNonLocked() {
        return false;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return false;
    }

    @Override
    public boolean isEnabled() {
        return false;
    }
}

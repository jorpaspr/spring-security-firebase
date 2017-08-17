package io.github.awaters1.security.model;

import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Data
@EqualsAndHashCode(callSuper = false)
public class FirebaseAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = 1L;

    private final String token;

    public FirebaseAuthenticationToken(final String token) {
        super(null, null);
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}

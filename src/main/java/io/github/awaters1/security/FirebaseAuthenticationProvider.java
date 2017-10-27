package io.github.awaters1.security;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import io.github.awaters1.security.model.FirebaseAuthenticationToken;
import io.github.awaters1.security.model.FirebaseUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutionException;

@Component
public class FirebaseAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirebaseAuthenticationProvider.class);

    private final FirebaseAuth firebaseAuth;

    public FirebaseAuthenticationProvider(FirebaseAuth firebaseAuth) {
        this.firebaseAuth = firebaseAuth;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (FirebaseAuthenticationToken.class.isAssignableFrom(authentication));
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    @Override
    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        final FirebaseAuthenticationToken authenticationToken = (FirebaseAuthenticationToken) authentication;
        try {
            FirebaseToken token = firebaseAuth.verifyIdTokenAsync(authenticationToken.getToken()).get();
            LOGGER.info("Firebase ID token accepted for user with uid " + token.getUid());
            return new FirebaseUserDetails(token.getEmail(), token.getUid());
        } catch (InterruptedException | ExecutionException e) {
            String errorMessage = e.getCause() instanceof FirebaseAuthException ? e.getCause().getMessage() :
                    e.getMessage() != null ? e.getMessage() : "Could not verify auth token";
            LOGGER.info(errorMessage);
            throw new SessionAuthenticationException(errorMessage);
        }
    }
}

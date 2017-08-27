package io.github.awaters1.security;

import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseToken;
import io.github.awaters1.security.model.FirebaseAuthenticationToken;
import io.github.awaters1.security.model.FirebaseUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Component;

import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

@Component
public class FirebaseAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(FirebaseAuthenticationProvider.class);

    private FirebaseAuth firebaseAuth;

    @Autowired
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
        final CompletableFuture<FirebaseToken> future = new CompletableFuture<>();
        firebaseAuth.verifyIdToken(authenticationToken.getToken())
                .addOnSuccessListener(result -> {
                    future.complete(result);
                    LOGGER.info("Firebase ID token accepted");
                })
                .addOnFailureListener(e -> {
                    future.cancel(true);
                    LOGGER.info(e.getMessage() != null ? e.getMessage() : "Invalid Firebase ID token");
                });
        try {
            final FirebaseToken token = future.get();
            return new FirebaseUserDetails(token.getEmail(), token.getUid());
        } catch (CancellationException e) {
            throw new SessionAuthenticationException("Invalid auth token");
        } catch (InterruptedException | ExecutionException e) {
            throw new SessionAuthenticationException("Could not verify auth token");
        }
    }
}

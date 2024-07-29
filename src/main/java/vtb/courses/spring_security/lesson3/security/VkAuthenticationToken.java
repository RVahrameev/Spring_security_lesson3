package vtb.courses.spring_security.lesson3.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * VkAuthenticationToken - класс для хранения информации по аутентифицированному в ВК пользователю
 */
public class VkAuthenticationToken implements Authentication {
    private boolean isAuthenticated;
    private String details;
    private String userName;

    public VkAuthenticationToken(boolean isAuthenticated, String details, String userName) {
        this.isAuthenticated = isAuthenticated;
        this.details = details;
        this.userName = userName;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return userName;
    }
}

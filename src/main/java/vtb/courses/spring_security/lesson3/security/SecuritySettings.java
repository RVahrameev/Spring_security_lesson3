package vtb.courses.spring_security.lesson3.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.io.IOException;
import java.util.Map;

/**
 * SecuritySettings - полная конфигурация системы доступа
 */
@Component
public class SecuritySettings {
    final String VK_OAUTH_CLIENT_ID = "52036067";
    final String OAUTH_REDIRECT_URL = "https://localhost/oauth/authorize";
    int state = 21346;

    private static void  handleException(HttpServletRequest request, HttpServletResponse response, RequestRejectedException requestRejectedException) throws IOException, ServletException {
        System.out.println("Exception: " + requestRejectedException);
    }

    @Bean
    public WebSecurityCustomizer initSecurity() {

        return web -> web
                .requestRejectedHandler(SecuritySettings::handleException)
                ;
    }
    class VkAuthenticationEntryPoint implements AuthenticationEntryPoint {

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
//            response.setContentType("application/json;charset=UTF-8");
//            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            response.getWriter().write("{\"message\": \"Please log in to access this resource.\"}");
            response.sendRedirect("https://oauth.vk.com/authorize?client_id=%s&redirect_uri=%s&scope=email&response_type=code&state=%d&v=5.131".formatted(VK_OAUTH_CLIENT_ID, OAUTH_REDIRECT_URL, state));
        }
    }

    /**
     * WhiteListFilter - кастомный фильтр осуществляющий логику доступа по "Белому списку"
     * Не вынесен в отдельный файл, т.к. иначе Spring Security автоматически его цепляет и
     * начинает применять к каждой странице сайта
     */
    class VkAuthorizeAcceptFilter implements Filter {
        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            System.out.println("session: " + ((HttpServletRequest)servletRequest).getSession().getId());
            Map<String,String[]> paramMap = servletRequest.getParameterMap();
            for (Map.Entry<String,String[]> el: servletRequest.getParameterMap().entrySet()) {
                String[] values = el.getValue();
                System.out.println(el.getKey()+":");
                for (String s: values) {
                    System.out.println("    " + s);
                }
            }
//            if  (
//                    servletRequest instanceof HttpServletRequest
//                            &&
//                            servletRequest.
//                            !urlMatcher.checkUrl(((HttpServletRequest)servletRequest).getHeader("referer"))
//            )
//            {
//                throw new WhiteListAccessException("");
//            } else {
//                filterChain.doFilter(servletRequest, servletResponse);
//            }
        }
    }


    @Bean @Order(1)
    SecurityFilterChain vkAuthorizeAcceptFilter(HttpSecurity http) throws Exception{
        return http
                .securityMatcher("/oauth/authorize**")
                .addFilterAfter(new VkAuthorizeAcceptFilter(), LogoutFilter.class)
                .build();
    }

    @Bean @Order(2)
    SecurityFilterChain filterChainAuthenticatedAccessOnly(HttpSecurity http) throws Exception{

        return http
                .logout(LogoutConfigurer::permitAll)
                //.formLogin(c -> c.defaultSuccessUrl("/", true))
                .authorizeHttpRequests(c -> c
                        .anyRequest().authenticated()
                )
//                .exceptionHandling(c -> c.accessDeniedPage("/AccessDenied.html"))
                .exceptionHandling(c -> c.authenticationEntryPoint(new VkAuthenticationEntryPoint()))
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .build();
    }

}

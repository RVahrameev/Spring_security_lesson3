package vtb.courses.spring_security.lesson3.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

/**
 * SecuritySettings - полная конфигурация системы доступа
 */
@Component
public class SecuritySettings {
    final String VK_OAUTH_CLIENT_ID = "52036067";
    final String OAUTH_REDIRECT_URL = "https://localhost/oauth/authorize";
    final String VK_USER_INFO_URL = "https://id.vk.com/oauth2/user_info";
    final String USER_SECRET_KEY = "gBnMLxyXPkKPDAgiC2qU";

    /**
     * VkAuthorizeAcceptFilter - реализует обработку ответа об аутентификации от ВК,
     * формирует запрос токена к ВК и дополнительной информации по пользователю
     * Оформлен как внутренний класс, т.к. объявление его публичным приводит к
     * его неконтролируемомоу вызову Spring Security
     */
    public class VkAuthorizeAcceptFilter implements Filter {

        /**
         * getUserInfo - отправка в ВК запросов на получение токена и информации по пользователю
         */
        private void getUserInfo(ServletRequest servletRequest, String code) throws IOException {
            String details;
            RestClient vkClient = RestClient.create();
            // Получение токена от ВК, для запроса информации по пользователю
            VkAccessToken token = vkClient.get()
                    .uri("https://oauth.vk.com/access_token?client_id=%s&client_secret=%s&redirect_uri=%s&code=%s".formatted(VK_OAUTH_CLIENT_ID, USER_SECRET_KEY, OAUTH_REDIRECT_URL, code))
                    .accept(APPLICATION_JSON)
                    .retrieve()
                    .body(VkAccessToken.class);
            if (token != null) {
                details = "\n" + token;
                //System.out.println("result token request: " + token);

                // Запрос у ВК информации по пользователю
                String result = vkClient.post()
                        .uri(VK_USER_INFO_URL)
                        .header("access_token", token.getAccess_token())
                        .contentType(APPLICATION_FORM_URLENCODED)
                        //.body("client_id=%s&access_token=%s".formatted(VK_OAUTH_CLIENT_ID, token.getAccess_token()))
                        .body("client_id=%s".formatted(VK_OAUTH_CLIENT_ID))
                        .accept(APPLICATION_JSON)
                        .retrieve()
                        .body(String.class);
                details = details + "\n " + result;
                //System.out.println("result user_info: " + result);
            } else {
                details = "Не удалось получить токен у VK";
            }

            // К сожалению, от ВК не удалось добиться положительного ответа
            // запрос информации по пользователю абортируется с сообщением "access_token is missing or invalid"
            // Поэтому далее просто иммитируем успех, а ответы от ВК выводим на страницу информации
            SecurityContextHolder.getContext().setAuthentication(new VkAuthenticationToken(true, details, "vk_user", token));
            ((HttpServletRequest)servletRequest).getSession().setAttribute(SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        }
        @Override
        public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
            // Получим из сессии сохранённый ранее state для обмена с ВК
            String saved_state = ((HttpServletRequest)servletRequest).getSession().getAttribute("auth_state").toString();
            //System.out.println("session auth_state:" + saved_state);

            Map<String,String[]> paramMap = servletRequest.getParameterMap();
//            for (Map.Entry<String,String[]> el: paramMap.entrySet()) {
//                String[] values = el.getValue();
//                System.out.println(el.getKey()+":");
//                for (String s: values) {
//                    System.out.println("    " + s);
//                }
//            }
            if (paramMap.containsKey("code")) {
                String code = paramMap.get("code")[0];
                if (
                        paramMap.containsKey("state")
                        &&
                        paramMap.get("state")[0].equals(saved_state)
                ) {
                    getUserInfo(servletRequest, code);
                } else {
                    throw new IllegalStateException("Ключ безопасности полученный от VK не соответствует ожидаемому!");
                }
            } else {
                throw new IllegalArgumentException("В ответе от VK отсутствуюет код безопасности");
            }
            //Перенаправляем на страницу информации о результатах аутентификации и получения информации по пользователю
            ((HttpServletResponse)servletResponse).sendRedirect("info");
        }
    }

    private static void  handleException(HttpServletRequest request, HttpServletResponse response, RequestRejectedException requestRejectedException) throws IOException, ServletException {
        System.out.println("Exception: " + requestRejectedException);
    }

    @Bean
    public WebSecurityCustomizer initSecurity() {

        return web -> web
                .requestRejectedHandler(SecuritySettings::handleException)
                .httpFirewall(new StrictHttpFirewall())
                ;
    }
    class VkAuthenticationEntryPoint implements AuthenticationEntryPoint {

        @Override
        public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
            // Генерим случайное число для state
            Integer state = Integer.valueOf((int) (Math.random() * 899999 + 100000));
            // Сохраняем его значение в текущей сессии
            request.getSession().setAttribute("auth_state", state.toString());
            // Перенаправляем пользователя на аутентификацию в ВК
            response.sendRedirect("https://oauth.vk.com/authorize?client_id=%s&redirect_uri=%s&scope=email&response_type=code&state=%d".formatted(VK_OAUTH_CLIENT_ID, OAUTH_REDIRECT_URL, state));
            //System.out.println("maked state: "+state);
        }
    }

    /**
     *  Настройка фильтра для обработки ответа от ВК
     */
    @Bean @Order(1)
    SecurityFilterChain vkAuthorizeAcceptFilter(HttpSecurity http) throws Exception{
        return http
                .securityMatcher("/oauth/authorize**")
                .addFilterAfter(new VkAuthorizeAcceptFilter(), LogoutFilter.class)
                .build();
    }

    /**
     * Настраиваем параметры безопасности:
     * - только аутенифицированный доступ
     * - всегда создавать сессию
     * - в качестве Аутентификации по умолчанию использовать VkAuthenticationEntryPoint
     */
    @Bean @Order(2)
    SecurityFilterChain filterChainAuthenticatedAccessOnly(HttpSecurity http) throws Exception{

        return http
                .logout(LogoutConfigurer::permitAll)
                .authorizeHttpRequests(c -> c
                        .anyRequest().authenticated()
                )
                .exceptionHandling(c -> c.authenticationEntryPoint(new VkAuthenticationEntryPoint()))
                .sessionManagement(c -> c.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .build();
    }

}

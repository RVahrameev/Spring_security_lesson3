package vtb.courses.spring_security.lesson3.security;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AccessToken {
    private String access_token;
    private Integer expires_in;
    private String user_id;
    private String error;
    private String error_description;
}

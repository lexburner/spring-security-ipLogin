package hello;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by xujingfeng on 2017/9/26.
 */
public class IpAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    protected IpAuthenticationProcessingFilter() {
        super(new AntPathRequestMatcher("/ipVerify"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String host = request.getRemoteHost();

        Authentication authentication = this.getAuthenticationManager().authenticate(new IpAuthenticationToken(host));
        return authentication;
    }
}

package hello;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;

/**
 * Created by xujingfeng on 2017/3/31.
 */
@Controller
public class HelloController {

    @Autowired
    AuthenticationManager authenticationManager;


    @RequestMapping("/hello1")
    @ResponseBody
    public String hello(HttpServletRequest request){
        System.out.println(request.getRemoteUser());
        System.out.println(request.getUserPrincipal());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("==========");
        return "hello1";
    }

}

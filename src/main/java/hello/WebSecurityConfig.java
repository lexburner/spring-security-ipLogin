package hello;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    IpAuthenticationProvider ipAuthenticationProvider() {
        return new IpAuthenticationProvider();
    }


    IpAuthenticationProcessingFilter ipAuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
        IpAuthenticationProcessingFilter ipAuthenticationProcessingFilter = new IpAuthenticationProcessingFilter();
        ipAuthenticationProcessingFilter.setAuthenticationManager(authenticationManager);
        return ipAuthenticationProcessingFilter;
    }

    @Bean
    LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint(){
        LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint = new LoginUrlAuthenticationEntryPoint
                ("/ipLogin");
        return loginUrlAuthenticationEntryPoint;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
                .antMatchers("/", "/home").permitAll()
                .antMatchers("/ipLogin").permitAll()
                .anyRequest().authenticated()
                .and()
            .logout()
                .logoutSuccessUrl("/")
                .permitAll()
                .and()
            .exceptionHandling()
                .accessDeniedPage("/ipLogin")
                .authenticationEntryPoint(loginUrlAuthenticationEntryPoint())
        ;

        http.addFilterBefore(ipAuthenticationProcessingFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.
//                inMemoryAuthentication()
//                .withUser("admin")
//                .password("admin")
//                .roles("USER");
        auth.authenticationProvider(ipAuthenticationProvider());
    }


//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        super.configure(web);
//    }


//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
////        JdbcUserDetailsManagerConfigurer jdbcUserDetailsManagerConfigurer = auth.jdbcAuthentication().dataSource(dataSource).passwordEncoder(new StandardPasswordEncoder());
//        JdbcUserDetailsManagerConfigurer jdbcUserDetailsManagerConfigurer = auth.jdbcAuthentication().dataSource
//                (dataSource).passwordEncoder(new PlaintextPasswordEncoder());
//
//        JdbcUserDetailsManager jdbcUserDetailsManager = jdbcUserDetailsManagerConfigurer.getUserDetailsService();
//        jdbcUserDetailsManager.setDataSource(dataSource);
////        jdbcUserDetailsManager.setGroupAuthoritiesByUsernameQuery(securitySqlProperties.getGroupAuthoritiesByUsernameQuery());
////        jdbcUserDetailsManager.setAuthoritiesByUsernameQuery(securitySqlProperties.getAuthoritiesByUsernameQuery());
////        jdbcUserDetailsManager.setUsersByUsernameQuery(securitySqlProperties.getUsersByUsernameQuery());
//        jdbcUserDetailsManager.setEnableGroups(false);
//
//
//
//    }

}
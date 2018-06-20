package top.kwseeker.springsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

//WebMvcConfigurer是Spring的配置类，里面可以配置Web应用的一些功能
//@EnableWebSecurity
//public class SecurityConfig implements WebMvcConfigurer {
//
//    /**
//     *  参考：5.1 Hello Web Security Java Configuration
//     *  这里提供了一个最简配置，虽然配置的东西比较少，但是框架做了很多其他默认的配置
//     *  1. 要求应用中所有URL都需要认证才能访问
//     *  2. 自动生成一个登陆表单
//     *  3. 允许用户注销
//     *  4. 自带CSRF攻击防御（跨站点请求伪造）
//     *  5. 会话固定保护（会话固定攻击：攻击者将自己的session id 加入到网络链接中，诱导其他人使用有效的用户名密码访问）
//     *  6. Security Header 集成 （？）
//     *  7. 集成下述 Servlet API （getRemoteUser getUserPrincipal isUserInRole login logout）
//     * @return
//     * @throws Exception
//     */
//    @Bean
//    public UserDetailsService userDetailsService() throws Exception {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withDefaultPasswordEncoder().username("Arvin").password("123456").roles("USER").build());
//        return manager;
//    }
//}

////WebSecurityConfigurerAdapter是默认情况下 spring security 的 http 配置。
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 参考： 5.2 5.3 5.4 5.5
     * HttpSecurity Http请求安全控制
     * 同样 Spring Security 也提供了默认的配置（WebSecurityConfigurerAdapter）
     * 1. 确保对我们的应用程序的任何请求都要求用户进行身份验证
     * 2. 允许用户使用基于表单的登录进行身份验证
     * 3. 允许用户使用 HTTP Basic 认证进行身份验证
     *
     * 对用户注销（Logout）的处理
     * 默认操作为：
     * 1. 使HTTP Session无效化
     * 2. 清理RememberMe认证配置
     * 3. 清理SecurityContextHolder (?)
     * 4. 重定向到 /login?logout (? 这种写法是什么意思)
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/css/**", "/index", "/").permitAll()
                    .antMatchers("/user/**").access("hasRole('USER') or hasRole('ADMIN')")
                    .anyRequest().authenticated()   //要求除了上述指定的URL其余所有的请求都要认证
                    .and()
                .formLogin()                        //基于表单的登录
                    .loginPage("/login").failureUrl("/login-error").permitAll()     //指定登录页面为login.html,所有人都可以访问
                    .and()
                .logout()                           //用户注销的配置
                    //.logoutUrl("/logout")                //触发注销的URL,默认为 /logout, 如果开启CSRF防护需要以POST方式请求才会有效
                    .logoutSuccessUrl("/index")          //成功注销之后重定向到的页面，这里指定为主页
                    //.logoutSuccessHandler(logoutSuccessHandler)   //自定义注销处理，会替代 logoutSuccessUrl()
                    //.addLogoutHandler(logoutHandler)    //
                    //.deleteCookies(cookieNameToClear)   //用户注销时删除指定的cookie
                    .invalidateHttpSession(true);       //默认就是true,所以这句可不写
    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/css/**", "/index").permitAll()
//                .antMatchers("/user/**").hasRole("USER")
//                .and()
//                .formLogin().loginPage("/login").failureUrl("/login-error");
//    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser(User.withDefaultPasswordEncoder().username("Arvin").password("123456").roles("USER"))
                .withUser(User.withDefaultPasswordEncoder().username("Admin").password("123456").roles("ADMIN"));
//                .withUser("kwseeker").password("123456").roles("USER");   // 这两种方式的区别？
    }

}
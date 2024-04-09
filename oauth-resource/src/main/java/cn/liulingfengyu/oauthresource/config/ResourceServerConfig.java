package cn.liulingfengyu.oauthresource.config;

import cn.liulingfengyu.oauthresource.handler.UnAccessDeniedHandler;
import cn.liulingfengyu.oauthresource.handler.UnAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

    /**
     * 资源管理器配置
     *
     * @param http
     * @return {@link SecurityFilterChain}
     * @author Fan
     * @since 2023/2/2 9:30
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        UnAuthenticationEntryPoint authenticationEntryPoint = new UnAuthenticationEntryPoint();
        UnAccessDeniedHandler accessDeniedHandler = new UnAccessDeniedHandler();

        http
                // security的session生成策略改为security不主动创建session, 即STALELESS
                // 资源服务不涉及用户登录, 仅靠token访问, 不需要seesion
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        // 对 /resource1 的请求，需要 SCOPE_message.read 权限
                        .antMatchers("/resource1").hasAuthority("SCOPE_message.read")
                        // 对 /resource2 的请求，需要 SCOPE_message.write 权限
                        .antMatchers("/resource2").hasAuthority("SCOPE_message.write")
                        // 对 /resource3 的请求，需要 SCOPE_profile 权限
                        .antMatchers("/resource3").hasAuthority("SCOPE_profile")
                        // 放行请求
                        .antMatchers("/api/**").permitAll()
                        // 其他任何请求都需要认证
                        .anyRequest().authenticated())
                // 异常处理器
                .exceptionHandling(exceptionConfigurer -> exceptionConfigurer
                        // 认证失败
                        .authenticationEntryPoint(authenticationEntryPoint)
                        // 鉴权失败
                        .accessDeniedHandler(accessDeniedHandler)
                )
                // 资源服务
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                        .jwt());

        return http.build();
    }
}

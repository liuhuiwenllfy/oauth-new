package cn.liulingfengyu.oauthserver.utils;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

public class OAuth2AuthenticationProviderUtils {
    private OAuth2AuthenticationProviderUtils() {
    }

    public static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        // 定义一个OAuth2ClientAuthenticationToken类型的变量clientPrincipal，用于存储客户端主体
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        // 判断authentication中的主体是否为OAuth2ClientAuthenticationToken类型
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            // 如果是，则将其转换为OAuth2ClientAuthenticationToken类型，并赋值给clientPrincipal
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        // 判断clientPrincipal是否不为null且已经认证通过
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            // 如果是，则返回clientPrincipal
            return clientPrincipal;
        } else {
            // 否则，抛出OAuth2AuthenticationException异常，表示客户端无效
            throw new OAuth2AuthenticationException("invalid_client");
        }
    }

}

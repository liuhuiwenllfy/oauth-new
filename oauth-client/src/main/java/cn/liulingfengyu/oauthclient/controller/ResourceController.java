package cn.liulingfengyu.oauthclient.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class ResourceController {

    @GetMapping("/server/a/resource1")
    public String getServerARes1(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://127.0.0.1:8001/resource1", oAuth2AuthorizedClient);
    }

    @GetMapping("/server/a/resource2")
    public String getServerARes2(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://127.0.0.1:8001/resource2", oAuth2AuthorizedClient);
    }

    @GetMapping("/server/a/resource3")
    public String getServerBRes1(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://127.0.0.1:8001/resource3", oAuth2AuthorizedClient);
    }

    @GetMapping("/server/a/publicResource")
    public String getServerBRes2(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return getServer("http://127.0.0.1:8001/api/publicResource", oAuth2AuthorizedClient);
    }

    /**
     * 绑定token，请求微服务
     */
    private String getServer(String url, OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        log.info("getServer");
        // 获取 access_token
        String tokenValue = oAuth2AuthorizedClient.getAccessToken().getTokenValue();

        // 发起请求
        Mono<String> stringMono = WebClient.builder()
                .defaultHeader("Authorization", "Bearer " + tokenValue)
                .build()
                .get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class);

        return stringMono.block();
    }
}

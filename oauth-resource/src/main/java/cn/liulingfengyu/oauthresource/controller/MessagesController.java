package cn.liulingfengyu.oauthresource.controller;

import cn.liulingfengyu.oauthresource.utils.RespJson;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessagesController {

    @GetMapping("/resource1")
    public RespJson<String> getResource1(){
        return RespJson.success("服务A -> 资源1 -> 读权限");
    }

    @GetMapping("/resource2")
    public RespJson<String> getResource2(){
        return RespJson.success("服务A -> 资源2 -> 写权限");
    }

    @GetMapping("/resource3")
    public RespJson<String> resource3(){
        return RespJson.success("服务A -> 资源3 -> profile 权限");
    }

    @GetMapping("/api/publicResource")
    public RespJson<String> publicResource() {
        return RespJson.success("服务A -> 公共资源");
    }
}

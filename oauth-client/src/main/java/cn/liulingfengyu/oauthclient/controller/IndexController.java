package cn.liulingfengyu.oauthclient.controller;

import cn.hutool.json.JSONUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class IndexController {

    @GetMapping("/")
    public String root() {
        return "redirect:/index";
    }

    @GetMapping("/index")
    public String index(Model model) {
        Map<String, Object> map = new HashMap<>();

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        map.put("name", auth.getName());

        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        List<? extends GrantedAuthority> authoritiesList = authorities.stream().collect(Collectors.toList());
        map.put("authorities", authoritiesList);

        model.addAttribute("user", JSONUtil.toJsonStr(map));
        return "index";
    }
}


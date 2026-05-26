package top.whgojp.modules.logic.idor.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;

/**
 * @description 逻辑漏洞-垂直越权
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/28 22:06
 */
@Slf4j
@Api(value = "VerticalController", tags = "逻辑漏洞-垂直越权")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/logic/idor/vertical")
public class VerticalController {
    @RequestMapping("")
    public String vertical() {
        return "vul/logic/idor/vertical";
    }

    @GetMapping("/vul")
    public String vul() {
        // 漏洞点：只要知道管理员功能地址即可直接访问，没有做服务端角色校验。
        return "vul/logic/idor/admin";
    }

    @GetMapping("/safe")
    @ResponseBody
    public R safe() {
        String currentUsername = SecurityContextHolder.getContext().getAuthentication().getName();
        if ("admin".equals(currentUsername)) {
            return R.ok("管理员权限校验通过");
        }
        return R.error("当前用户无管理员权限：" + currentUsername);
    }

}

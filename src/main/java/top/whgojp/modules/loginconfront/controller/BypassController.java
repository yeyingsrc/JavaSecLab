package top.whgojp.modules.loginconfront.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpSession;
import java.util.*;

/**
 * @description 登录对抗-登录绕过
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/11/19 21:01
 */
@Slf4j
@Api(value = "BypassController", tags = "登录对抗-登录绕过")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/loginconfront/bypass")
public class BypassController {
    @RequestMapping("")
    public String bypass() {
        return "vul/loginconfront/bypass";
    }

    @RequestMapping("/reset")
    public String reset() {
        return "vul/loginconfront/resetpass";
    }

    // 测试账号密码
    private static final String REAL_USERNAME = "admin";
    private static final String REAL_PASSWORD = "admin123";
    private static final String RESET_FLOW_DATA = "loginconfrontResetFlowData";

    @PostMapping("/vul1step1")
    @ResponseBody
    public R vul1step1(String username, String password) {
        if (username == null || username.trim().isEmpty() || password == null) {
            return R.error("账号校验失败，请重试！");
        }
        if (REAL_USERNAME.equalsIgnoreCase(username) && REAL_PASSWORD.equalsIgnoreCase(password)) {
            return R.ok("账号校验通过，请稍等！");
        } else {
            return R.error("账号校验失败，请重试！");
        }
    }

    @PostMapping("/vul1step2")
    @ResponseBody
    public R vul1step2(String code) {
        if ("0".equals(code)) {
            return R.ok("登录成功，欢迎！");
        } else {
            return R.error("登录失败！");
        }
    }

    private static final String OLD_PASS = "!@#qwf@3123";

    // step1:验证用户名
    @PostMapping("/step1")
    @ResponseBody
    public R vul2Step1(@RequestParam String username, HttpSession session) {
        try {
            log.info("用户名：" + username);
            if (username == null || username.trim().isEmpty()) {
                return R.error("用户名不能为空");
            }
            flowData(session).put(1, username);
            return R.ok("用户名验证成功！");
        } catch (Exception e) {
            return R.error("服务器错误，请稍后再试");
        }
    }


    // step2:验证旧密码
    @PostMapping("/step2")
    @ResponseBody
    public R vul2Step2(@RequestParam String oldPassword, HttpSession session) {
        if (oldPassword == null || oldPassword.isEmpty()) {
            return R.error("旧密码不能为空！");
        }
        if (!OLD_PASS.equals(oldPassword)) {
            return R.error("旧密码错误！");
        }
        flowData(session).put(2, oldPassword);
        return R.ok("密码验证成功！");
    }

    // step3:设置新密码
    @PostMapping("/step3")
    @ResponseBody
    public R vul2Step3(@RequestParam String newPassword, HttpSession session) {
        if (newPassword == null || newPassword.length() < 6) {
            return R.error("密码长度必须大于6!");
        }
        Map<Integer, String> stepData = flowData(session);
        stepData.put(3, newPassword);
        log.info("密码重置流程数据: {}", stepData);
        return R.ok("密码重置成功！");
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, String> flowData(HttpSession session) {
        Object data = session.getAttribute(RESET_FLOW_DATA);
        if (data instanceof Map) {
            return (Map<Integer, String>) data;
        }
        Map<Integer, String> stepData = new HashMap<>();
        session.setAttribute(RESET_FLOW_DATA, stepData);
        return stepData;
    }

}

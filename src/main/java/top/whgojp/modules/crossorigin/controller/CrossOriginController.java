package top.whgojp.modules.crossorigin.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.utils.R;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * @description 跨源安全问题
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/6/6 20:46
 */
@Slf4j
@Api(value = "CrossOriginController", tags = "跨域安全问题")
@Controller
//@CrossOrigin(origins = "*")
@RequestMapping("/crossorigin")
public class CrossOriginController {

    private static final Set<String> TRUSTED_ORIGINS = new HashSet<>(Arrays.asList(
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8080"
    ));
    private static final Pattern JSONP_CALLBACK_PATTERN = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*$");

    @RequestMapping("/cors")
    public String cors() {
        return "vul/crossorigin/cors";
    }
    @RequestMapping("/jsonp")
    public String jsonp() {
        return "vul/crossorigin/jsonp";
    }

    @RequestMapping(value = "/corsVul", method = {RequestMethod.GET, RequestMethod.OPTIONS})
    @ResponseBody
    public R corsVul(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("Origin");

        if (origin != null) {
            response.setHeader("Access-Control-Allow-Origin", origin);
        } else {
            response.setHeader("Access-Control-Allow-Origin", "http://example.com");
        }

        // 允许携带 Cookie 或其他凭证
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        response.setHeader("Vary", "Origin");

        return R.ok("CORS漏洞演示：username:admin,password:Admin123");
    }

    @RequestMapping(value = "/corsSafe", method = {RequestMethod.GET, RequestMethod.OPTIONS})
    @ResponseBody
    public R corsSafe(HttpServletRequest request, HttpServletResponse response) {
        String origin = request.getHeader("Origin");
        response.setHeader("Vary", "Origin");
        if (origin == null) {
            return R.ok("同源请求不需要CORS响应头");
        }
        if (!TRUSTED_ORIGINS.contains(origin)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return R.error(HttpServletResponse.SC_FORBIDDEN, "Origin不在CORS白名单");
        }
        response.setHeader("Access-Control-Allow-Origin", origin);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers", "Content-Type");
        return R.ok("配置CORS可信源白名单");
    }

    @GetMapping("/jsonpVul")
    public void jsonpVul(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String callback = request.getParameter("callback");
        String sensitiveData = "{\"username\":\"admin\",\"password\":\"Admin123\"}";

        // 返回数据包装成 JSONP 格式，并没有对 callback 参数进行安全验证
        String jsonpResponse = callback + "(" + sensitiveData + ");";

        // 设置响应类型为 JavaScript 脚本
        response.setContentType("application/javascript;charset=UTF-8");
        response.getWriter().write(jsonpResponse);
    }


    @GetMapping("/jsonpSafe")
    public void jsonpSafe(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String callback = request.getParameter("callback");

        // 校验回调函数名是否合法
        if (callback == null || !JSONP_CALLBACK_PATTERN.matcher(callback).matches()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Invalid callback");
            return;
        }

        String publicData = "{\"message\":\"public data only\"}";
        response.setContentType("application/javascript;charset=UTF-8");
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.getWriter().write(callback + "(" + publicData + ");");
    }


}

package top.whgojp.modules.springboot.controller;

import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import top.whgojp.common.utils.R;
import top.whgojp.modules.springboot.entity.MaliciousObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.*;

/**
 * @description java专题-SpringBoot相关漏洞
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/8/8 23:44
 */
@Slf4j
@Api(value = "SpringBootController", tags = "java专题-SpringBoot相关漏洞")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/springboot")
public class SpringBootController {
    @RequestMapping("")
    public String springboot() {
        return "vul/springboot/springboot";
    }

    @Value("${spring.datasource.url:jdbc:mysql://localhost:13306/JavaSecLab}")
    String legacyUrl = "";
    @Value("${spring.datasource.username:root}")
    String legacyUsername = "";
    @Value("${spring.datasource.password:QWE123qwe}")
    String legacyPassword = "";
    @Value("${spring.datasource.primary.url:}")
    String url = "";
    @Value("${spring.datasource.primary.username:}")
    String username = "";
    @Value("${spring.datasource.primary.password:}")
    String password = "";

    @RequestMapping("/jdbc")
    @ResponseBody
    public R jdbc() {
        try (Connection conn = DriverManager.getConnection(resolveUrl(), resolveUsername(), resolvePassword());
             Statement stmt = conn.createStatement()) {
            String selectQuery = "SELECT malicious_object FROM objects WHERE id = 1";

            try (ResultSet rs = stmt.executeQuery(selectQuery)) {
                if (!rs.next()) {
                    return R.error("未找到恶意对象，请先点击“反序列化命令”插入测试数据");
                }
                byte[] maliciousObjectBytes = rs.getBytes("malicious_object");
                if (maliciousObjectBytes == null || maliciousObjectBytes.length == 0) {
                    return R.error("恶意对象内容为空");
                }
                try (ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(maliciousObjectBytes))) {
                    objectInputStream.readObject();
                }
            }

            log.info("触发MYSQL-JDBC反序列化漏洞！");
            return R.ok("触发MYSQL-JDBC反序列化漏洞！");
        } catch (Exception e) {
            log.error("触发MYSQL-JDBC反序列化漏洞失败", e);
            return R.error("触发MYSQL-JDBC反序列化漏洞失败：" + e.getMessage());
        }
    }

    @RequestMapping("/insert")
    @ResponseBody
    public R insertMaliciousObject(@RequestParam String command) {
        if (command == null || command.trim().isEmpty()) {
            return R.error("命令不能为空");
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            MaliciousObject maliciousObject = new MaliciousObject(command);

            oos.writeObject(maliciousObject);
            byte[] objectBytes = baos.toByteArray();

            try (Connection conn = DriverManager.getConnection(resolveUrl(), resolveUsername(), resolvePassword());
                 PreparedStatement stmt = conn.prepareStatement("REPLACE INTO objects (id, malicious_object) VALUES (?, ?)")) {
                stmt.setInt(1, 1);
                stmt.setBytes(2, objectBytes);
                stmt.executeUpdate();
            }

            return R.ok("恶意对象插入成功！");
        } catch (Exception e) {
            log.error("恶意对象插入失败", e);
            return R.error("恶意对象插入失败：" + e.getMessage());
        }
    }

    @RequestMapping("/vul")
    @ResponseBody
    public R vul(String url, String username, String password) {
        if (url == null || url.trim().isEmpty()) {
            return R.error("JDBC URL不能为空");
        }

        try {
//            Class.forName("com.mysql.jdbc.Driver");
            Class.forName("com.mysql.cj.jdbc.Driver");
            DriverManager.setLoginTimeout(5);
            try (Connection ignored = DriverManager.getConnection(url, username, password)) {
                return R.ok("JDBC连接请求已发送");
            }
        } catch (Exception e) {
            log.error("JDBC连接失败", e);
            return R.error("JDBC连接失败：" + e.getMessage());
        }
    }

    private String resolveUrl() {
        return isBlank(url) ? legacyUrl : url;
    }

    private String resolveUsername() {
        return isBlank(username) ? legacyUsername : username;
    }

    private String resolvePassword() {
        return isBlank(password) ? legacyPassword : password;
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

}

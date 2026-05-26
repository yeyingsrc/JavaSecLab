package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.apache.log4j.lf5.util.StreamUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import top.whgojp.common.constant.SysConstant;


import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @description 任意文件类-文件下载
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:59
 */
@Slf4j
@Api(value = "DownloadController", tags = "任意文件类-文件下载")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/download")
public class DownloadController {
    @RequestMapping("")
    public String fileDownload() {
        return "vul/file/download";
    }

    @ApiOperation(value = "下载文件", notes = "下载指定文件")
    @RequestMapping("/vul")
    public void vul(@RequestParam("fileName") String fileName, HttpServletResponse response) throws IOException {
        File file = new File(fileName);

        if (file.exists() && file.isFile()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");
            try (FileInputStream fis = new FileInputStream(file);
                 OutputStream os = response.getOutputStream()) {
                StreamUtils.copy(fis, os);
                os.flush();
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在：" + fileName);
        }
    }

    @Autowired
    private SysConstant sysConstant;
    @RequestMapping("/safe")
    public void safe(@RequestParam("fileName") String fileName, HttpServletResponse response) throws IOException {
        String baseDir = sysConstant.getUploadFolder();
        if (!isValidFileName(fileName)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "非法文件名：" + fileName);
            return;
        }
        Path basePath = Paths.get(baseDir).toRealPath();
        Path filePath = basePath.resolve(fileName).normalize();
        if (filePath.startsWith(basePath) && Files.isRegularFile(filePath)) {
            Path realFilePath = filePath.toRealPath();
            if (!realFilePath.startsWith(basePath)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "文件真实路径不合法：" + fileName);
                return;
            }
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + realFilePath.getFileName().toString() + "\"");
            try (InputStream fis = Files.newInputStream(realFilePath);
                 OutputStream os = response.getOutputStream()) {
                StreamUtils.copy(fis, os);
                os.flush();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } else {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "文件不存在或不可访问：" + fileName);
        }
    }

    private boolean isValidFileName(String fileName) {
        return fileName != null && fileName.matches("^[\\w,\\s-]+\\.[A-Za-z]{3,4}$");
    }


}

package top.whgojp.modules.file.controller;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import top.whgojp.common.constant.SysConstant;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * @description 任意文件类-文件删除
 * @author: whgojp
 * @email: whgojp@foxmail.com
 * @Date: 2024/7/8 15:59
 */
@Slf4j
@Api(value = "DeleteController", tags = "任意文件类-文件删除")
@Controller
@CrossOrigin(origins = "*")
@RequestMapping("/file/delete")
public class DeleteController {
    @RequestMapping("")
    public String fileDelete() {
        return "vul/file/delete";
    }

    @ApiOperation(value = "漏洞场景：任意文件删除", notes = "原生漏洞场景，未做任何限制")
    @RequestMapping("/vul")
    @ResponseBody
    @SneakyThrows
    public String vul(@RequestParam("filePath") String filePath) {
        String currentPath = System.getProperty("user.dir");
        log.info("当前路径："+currentPath);
        File file = new File(filePath);
        boolean deleted = false;
        if (file.exists()) {
            deleted = file.delete();
        }
        if (deleted) {
            return "当前路径:"+currentPath+"<br/>文件删除成功: " + filePath;
        } else {
            return "当前路径:"+currentPath+"<br/>文件删除失败或文件不存在: " + filePath;
        }
    }

    @Autowired
    private SysConstant sysConstant;
    @ApiOperation(value = "安全场景：限制文件删除", notes = "仅允许删除特定目录中的文件")
    @RequestMapping("/safe")
    @ResponseBody
    @SneakyThrows
    public String safe(@RequestParam("fileName") String fileName) {
        String baseDir = sysConstant.getUploadFolder();
        Path basePath = Paths.get(baseDir).toRealPath();
        Path filePath = basePath.resolve(fileName).normalize();
        if (!filePath.startsWith(basePath)) {
            return "访问被拒绝：文件路径不合法";
        }
        boolean deleted = false;
        if (Files.isRegularFile(filePath)) {
            Path realFilePath = filePath.toRealPath();
            if (!realFilePath.startsWith(basePath)) {
                return "访问被拒绝：文件真实路径不合法";
            }
            deleted = Files.deleteIfExists(filePath);
        }
        if (deleted) {
            return "文件删除成功: " + fileName;
        } else {
            return "文件删除失败或文件不存在: " + fileName;
        }
    }


}

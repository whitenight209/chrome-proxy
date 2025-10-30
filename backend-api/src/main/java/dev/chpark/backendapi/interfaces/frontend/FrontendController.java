package dev.chpark.backendapi.interfaces.frontend;


import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
public class FrontendController {

    @GetMapping("/")
    public String root() {
        return "forward:/web/index.html";
    }
}

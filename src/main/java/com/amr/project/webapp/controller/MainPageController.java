package com.amr.project.webapp.controller;
import com.amr.project.model.dto.UserDto;
import com.amr.project.model.entity.User;
import com.amr.project.service.abstracts.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import com.amr.project.converter.CycleAvoidingMappingContext;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.UnsupportedEncodingException;
import java.util.List;

@Controller
@RequestMapping("/")
@RequiredArgsConstructor
@CrossOrigin
//Вывод представления
public class MainPageController {

    private final UserService userService;
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping
    public String returnMainPage (@AuthenticationPrincipal User user, Model model) {
        model.addAttribute("user", user);
        return "/index";
    }

    @GetMapping("/login1FA")
    public String preloginPage(Model model) {
        return "login1FA";
    }

    @GetMapping("/login1FAQR")
    public String postPage(@RequestParam String email, Model model) throws UnsupportedEncodingException {
        User user = userService.getUserByEmail(email);
        if (user.isUsing2FA()) {
            model.addAttribute("qrcode", userService.generateQRUrl(user));
            return "qrcode";
        }
        return  "redirect:/login";
    }
}

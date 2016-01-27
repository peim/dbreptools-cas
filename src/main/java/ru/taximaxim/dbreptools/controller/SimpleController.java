package ru.taximaxim.dbreptools.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class SimpleController {

    @RequestMapping("/login")
    public String login() {
        return "redirect:/";
    }
    
    @RequestMapping(value = { "/", "" }, method = RequestMethod.GET)
    public String index(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String user = auth.getName();
        model.addAttribute("user", user);
        System.err.println("user - " + user);

        return "index";
    }

    @RequestMapping(value = "/secure", method = RequestMethod.GET)
    public String secure(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String user = auth.getName();
        model.addAttribute("user", user);
        System.err.println("user - " + user);

        return "secure_page";
    }
    
    @RequestMapping(value = "/open", method = RequestMethod.GET)
    public String open(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String user = auth.getName();
        model.addAttribute("user", user);
        System.err.println("user - " + user);

        return "open_page";
    }
}
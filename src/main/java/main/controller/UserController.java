package main.controller;


import main.model.Role;
import main.model.User;
import main.service.ServiceUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collection;
import java.util.HashSet;

@Controller
public class UserController {
    @Autowired
    private ServiceUser serviceUser;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String greeting() {
//        Collection<? extends GrantedAuthority> authorities = SecurityContextHolder.getContext().getAuthentication().getAuthorities();
//        if (authorities.contains(Role.ADMIN)) {
            return "redirect:/admin/adminPage";
//        }
//        return "redirect:/user/userPageInfo";
    }
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/newAdmin")
    public String newAdmin() {
        HashSet<Role> roles = new HashSet<>();
        roles.add(Role.ADMIN);
        roles.add(Role.USER);
        User user = new User("ADMIN", passwordEncoder.encode("ADMIN"), "LastName", 23, "asasd@asd.ru", roles);
        serviceUser.save(user);
        return "/hello";
    }

    @RequestMapping(value = "/admin/adminPage", method = {RequestMethod.GET, RequestMethod.POST})
    public ModelAndView listUsers(User user) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        Iterable<User> list = serviceUser.findAll();
        ModelAndView modelAndView = new ModelAndView("adminPage");
        modelAndView.getModelMap().addAttribute("listUsers", list);
        modelAndView.getModelMap().addAttribute("currentUser", currentUser);
        return modelAndView;
    }

    @GetMapping("/user/userPageInfo")
    public ModelAndView printWelcome(User user) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        ModelAndView modelAndView = new ModelAndView("userPageInfo");
        modelAndView.getModelMap().addAttribute("currentUser", currentUser);
        return modelAndView;
    }
}

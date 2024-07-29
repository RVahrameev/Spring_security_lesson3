package vtb.courses.spring_security.lesson3.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;

@Controller
@EnableMethodSecurity
public class HttpController implements ErrorController {

	@GetMapping("/oauth/info")
	public String info(Model model) {
		// Вернём в страницу имя текущего пользователя и результат полученный от ВК
		model.addAttribute("name", SecurityContextHolder.getContext().getAuthentication().getName());
		model.addAttribute("vk_resul", SecurityContextHolder.getContext().getAuthentication().getDetails());
		return "info";
	}

//	@GetMapping("/oauth/authorize")
//	public String authorize(Model model) {
//		System.out.println("go to authorize page!");
//		// Вернём в страницу имя текущего пользователя
//		model.addAttribute("name", SecurityContextHolder.getContext().getAuthentication().getName());
//		model.addAttribute("vk_resul", SecurityContextHolder.getContext().getAuthentication().getDetails());
//		return "authorize.html";
//	}

}

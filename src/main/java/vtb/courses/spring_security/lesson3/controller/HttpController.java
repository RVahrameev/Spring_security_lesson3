package vtb.courses.spring_security.lesson3.controller;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

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

}

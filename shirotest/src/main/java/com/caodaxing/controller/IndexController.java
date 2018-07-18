package com.caodaxing.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class IndexController {
	
	@RequestMapping("login.jhtml")
	public String login() {
		return "login";
	}
	
	@RequestMapping("index.do")
	public String index() {
		return "index";
	}
	
}

package com.caodaxing.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.helpers.MDCKeySetExtractor;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.caodaxing.entity.LoginUser;
import com.caodaxing.entity.LoginUserExample;
import com.caodaxing.service.LoginUserService;
import com.caodaxing.utils.CommonFiledUtil;
import com.caodaxing.utils.HttpUtil;
import com.caodaxing.utils.MD5Utils;
import com.caodaxing.utils.MessageUtil;
import com.sun.mail.handlers.message_rfc822;

@Controller
public class LoginCheckController {
	
	private final Logger logger = LoggerFactory.getLogger(LoginCheckController.class);
	
	@Autowired
	private LoginUserService loginUserService;

	@RequestMapping("checkLogin.do")
	@ResponseBody
	public Map<String, Object> checkLogin(LoginUser loginUser,HttpServletRequest request,HttpServletResponse response) {
		logger.info("验证用户登录信息...");
		if(StringUtils.isBlank(loginUser.getUsername()) || StringUtils.isBlank(loginUser.getPassword())) {
			return MessageUtil.errorMessage("用户名或密码不能为空!");
		}
		String encryptedPassword = MD5Utils.getMD5(loginUser.getPassword());
		LoginUserExample example = new LoginUserExample();
		example.createCriteria().andUsernameEqualTo(loginUser.getUsername());
		List<LoginUser> loginUserList = loginUserService.selectByExample(example);
		if(loginUserList.size() > 0) {
			loginUser = loginUserList.get(0);
			if(!StringUtils.equals(encryptedPassword, loginUser.getPassword())) {
				return MessageUtil.errorMessage("密码错误!");
			}
			HttpSession session = request.getSession(true);
			session.setAttribute(CommonFiledUtil.USER_SESSION, loginUser);
			Subject sub = SecurityUtils.getSubject();
			UsernamePasswordToken upt = new UsernamePasswordToken(loginUser.getUsername(),encryptedPassword);
			sub.login(upt);
			return MessageUtil.successMessage("登录成功!");
		}
		return MessageUtil.errorMessage("该用户名不存在!");
	}
	
	@RequestMapping("/logout.do")
	@ResponseBody
	public boolean logout(HttpServletRequest request) {
		request.getSession().removeAttribute(CommonFiledUtil.USER_SESSION);
		Subject subject = SecurityUtils.getSubject();
		subject.logout();
		return true;
	}
	
	@RequestMapping("/test")
	public String test(){
		Map<String, Object> map = new HashMap<>();
		map.put("sss", "ss");
		map.put("aaa", "aa");
		return "test";
	}
	
}

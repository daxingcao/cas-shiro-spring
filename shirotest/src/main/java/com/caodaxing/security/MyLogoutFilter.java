package com.caodaxing.security;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.web.filter.authc.LogoutFilter;
import org.apache.shiro.web.util.WebUtils;

import com.caodaxing.utils.CommonFiledUtil;

public class MyLogoutFilter extends LogoutFilter {

	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		//点击登录退出时,清除session中用户的数据
		HttpServletRequest http = WebUtils.toHttp(request);
		HttpSession session = http.getSession(true);
		session.removeAttribute(CommonFiledUtil.USER_SESSION);
		return super.preHandle(request, response);
	}

	
	
}

package com.caodaxing.utils;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import com.alibaba.fastjson.JSONObject;

public class HttpUtil {
	
	public static void outJson(HttpServletResponse response,Map<String, Object> params) {
		response.setContentType("application/json;charset=utf-8");
		response.setCharacterEncoding("UTF-8");
		try {
			PrintWriter writer = response.getWriter();
			writer.println(JSONObject.toJSONString(params));
			writer.flush();
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}

package com.caodaxing.utils;

import java.util.HashMap;
import java.util.Map;

public class MessageUtil {
	
	private String code;
	
	private String msg;
	
	private Object result;
	
	public MessageUtil() {}
	
	public MessageUtil(String code,String msg) {
		this.code = code;
		this.msg = msg;
	}
	
	public MessageUtil(String msg) {
		this.msg = msg;
	}
	
	public MessageUtil(String msg,Object result) {
		this.msg = msg;
		this.result = result;
	}
	
	public MessageUtil(String code,String msg,Object result) {
		this.code = code;
		this.msg = msg;
		this.result = result;
	}
	
	public static Map<String, Object> errorMessage(String msg) {
		Map<String, Object> map = new HashMap<>();
		map.put("msg", msg);
		map.put("success",false);
		map.put("code", CommonFiledUtil.FAIL_CODE);
		return map;
	}
	
	public static Map<String, Object> errorMessage(String msg,String code){
		Map<String, Object> map = errorMessage(msg);
		map.put("code", code);
		return map;
	}
	
	public static Map<String, Object> errorMessage(String msg,Object result){
		Map<String, Object> map = errorMessage(msg);
		map.put("result", result);
		return map;
	}
	
	public static Map<String, Object> errorMessage(Object result){
		Map<String, Object> map = new HashMap<>();
		map.put("msg", CommonFiledUtil.DEFAULT_FAIL_MSG);
		map.put("code",CommonFiledUtil.FAIL_CODE);
		map.put("success", false);
		map.put("result", result);
		return map;
	}
	
	public static Map<String, Object> errorMessage(String msg,String code,Object result){
		Map<String, Object> map = new HashMap<>();
		map.put("msg", msg);
		map.put("code", code);
		map.put("result", result);
		map.put("success", false);
		return map;
	}
	
	public static Map<String, Object> successMessage(String msg){
		Map<String, Object> map = new HashMap<>();
		map.put("msg", msg);
		map.put("success",true);
		map.put("code", CommonFiledUtil.SUCCESS_CODE);
		return map;
	}
	
	public static Map<String, Object> successMessage(String msg,String code){
		Map<String, Object> map = successMessage(msg);
		map.put("code", code);
		return map;
	}
	
	public static Map<String, Object> successMessage(String msg,Object result){
		Map<String, Object> map = successMessage(msg);
		map.put("result", result);
		return map;
	}
	
	public static Map<String, Object> successMessage(Object result){
		Map<String, Object> map = new HashMap<>();
		map.put("msg", CommonFiledUtil.DEFAULT_SUCCESS_MSG);
		map.put("code",CommonFiledUtil.SUCCESS_CODE);
		map.put("success", true);
		map.put("result", result);
		return map;
	}
	
	public static Map<String, Object> successMessage(String msg,String code,Object result){
		Map<String, Object> map = new HashMap<>();
		map.put("msg", msg);
		map.put("code", code);
		map.put("result", result);
		map.put("success", true);
		return map;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getMsg() {
		return msg;
	}

	public void setMsg(String msg) {
		this.msg = msg;
	}

	public Object getResult() {
		return result;
	}

	public void setResult(Object result) {
		this.result = result;
	}

}

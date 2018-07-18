package com.caodaxing.utils;

import org.mybatis.generator.api.IntrospectedColumn;
import org.mybatis.generator.api.IntrospectedTable;
import org.mybatis.generator.api.dom.java.Field;
import org.mybatis.generator.api.dom.java.Method;
import org.mybatis.generator.api.dom.xml.XmlElement;
import org.mybatis.generator.internal.DefaultCommentGenerator;
import org.mybatis.generator.internal.util.StringUtility;

public class MyCommentGenerator extends DefaultCommentGenerator {

	private boolean USER_DEFINED_FLAG = true;
	
	/**
	 * 实体类生成字段注解自定义
	 */
	@Override
	public void addFieldComment(Field field, IntrospectedTable table, IntrospectedColumn column) {
		if(USER_DEFINED_FLAG) {
			if(StringUtility.stringHasValue(column.getRemarks())) {
				field.addJavaDocLine("/**");
				field.addJavaDocLine(" * "+column.getRemarks());
				field.addJavaDocLine(" */");
			}
		}else {
			super.addFieldComment(field, table, column);
		}
	}

	/**
	 * mapper映射文件注解自定义
	 */
	@Override
	public void addComment(XmlElement xmlElement) {
		if (USER_DEFINED_FLAG) {
			return;
		}else {
			super.addComment(xmlElement);
		}
	}

	/**
	 * dao层接口注释自定义
	 */
	@Override
	public void addGeneralMethodComment(Method method, IntrospectedTable introspectedTable) {
		if (USER_DEFINED_FLAG) {
			return;
		}else {
			super.addGeneralMethodComment(method, introspectedTable);
		}
	}

	/**
	 * 实体类getter方法注解自定义
	 */
	@Override
	public void addGetterComment(Method method, IntrospectedTable introspectedTable,
			IntrospectedColumn introspectedColumn) {
		if (USER_DEFINED_FLAG) {
			
		}else {
			super.addGetterComment(method, introspectedTable, introspectedColumn);
		}
	}

	/**
	 * 实体类setter方法注解自定义
	 */
	@Override
	public void addSetterComment(Method method, IntrospectedTable introspectedTable,
			IntrospectedColumn introspectedColumn) {
		if (USER_DEFINED_FLAG) {
			return;
		} else {
			super.addSetterComment(method, introspectedTable, introspectedColumn);
		}
	}

}

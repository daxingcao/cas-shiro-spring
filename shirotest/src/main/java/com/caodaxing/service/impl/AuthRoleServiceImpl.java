package com.caodaxing.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.caodaxing.dao.AuthRoleMapper;
import com.caodaxing.entity.AuthRole;
import com.caodaxing.entity.AuthRoleExample;
import com.caodaxing.service.AuthRoleService;

@Service
public class AuthRoleServiceImpl implements AuthRoleService {

	@Autowired
	private AuthRoleMapper authRoleMapper;
	
	@Override
	public long countByExample(AuthRoleExample example) {
		return authRoleMapper.countByExample(example);
	}

	@Override
	public int insert(AuthRole record) {
		return authRoleMapper.insert(record);
	}

	@Override
	public int insertSelective(AuthRole record) {
		return authRoleMapper.insertSelective(record);
	}

	@Override
	public List<AuthRole> selectByExample(AuthRoleExample example) {
		return authRoleMapper.selectByExample(example);
	}

	@Override
	public AuthRole selectByPrimaryKey(Long id) {
		return authRoleMapper.selectByPrimaryKey(id);
	}

	@Override
	public int updateByPrimaryKeySelective(AuthRole record) {
		return authRoleMapper.updateByPrimaryKeySelective(record);
	}

	@Override
	public int updateByPrimaryKey(AuthRole record) {
		return authRoleMapper.updateByPrimaryKey(record);
	}

}
